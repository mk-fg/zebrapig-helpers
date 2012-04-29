#!/usr/bin/env python

import itertools as it, operator as op, functools as ft
from glob import glob
from fnmatch import fnmatch
from hashlib import sha1
from io import open
import os, sys, re, logging

from twisted.internet import inotify, reactor, protocol, defer
from twisted.internet.utils import getProcessOutputAndValue
from twisted.web.client import downloadPage
from twisted.python.filepath import FilePath
from twisted.python import log


class PasteGrabber(object):

	@staticmethod
	def file_end_mark(path, size=200, pos=None, data=None):
		if not pos:
			with path.open() as src:
				if not data:
					pos = None
					while pos != src.tell(): # to ensure that file didn't grow in-between
						pos = os.fstat(src.fileno()).st_size
						src.seek(-min(pos, size), os.SEEK_END)
						data = src.read()
				else:
					pos = os.fstat(src).st_size
		size, data = len(data), sha1(data).hexdigest()
		return pos, size, data

	@staticmethod
	def file_end_check(path, pos, size=None, data=None):
		if pos != path.getsize(): return False
		elif size and data:
			with path.open() as src:
				src.seek(-size, os.SEEK_END)
				if sha1(src.read()).hexdigest() != data: return False
		return True


	def __init__(self, path_mask, dst_path):
		self.dst_path = FilePath(dst_path)

		paths_pos = self.paths_pos = dict()
		paths_watch = self.paths_watch = dict()
		self.paths_buff = dict()

		self.notifier = inotify.INotify()
		self.notifier.startReading()

		paths = glob(path_mask)

		for path in it.imap(FilePath, paths):
			path_real = path.realpath()
			# Matched regular files are watched as a basename pattern in the dir
			if path_real.isfile():
				path_dir = path.parent().realpath()
				if path_dir not in paths_watch:
					paths_watch[path_dir] = {os.path.basename(optz.path_mask)}
				else: paths_watch[path_dir].add(os.path.basename(optz.path_mask))
			# All files in the matched dirs are watched, non-recursively
			elif path_real.isdir():
				if path_real not in paths_watch: paths_watch[path_real] = {'*'}
				else: paths_watch[path_real].add('*')
				for name in path_real.listdir():
					path_child = path_real.child(name).realpath()
			# Specials of any kind are ignored
			else: log.debug('Skipping non-file/dir path: {}'.format(path_real))

		for path in paths_watch:
			log.debug('Adding watcher to path: {}'.format(path))
			self.notifier.watch( path,
				mask=inotify.IN_CREATE | inotify.IN_MODIFY,
				callbacks=[self.handle_change] )


	def handle_change(self, stuff, path, mask):
		# log.debug('Event: {} ({})'.format(
		# 	path, inotify.humanReadableMask(mask) ))

		## Filtering
		path_real = path.realpath()
		if not path_real.isfile():
			log.debug( 'Ignoring event for'
				' non-regular file: {} (realpath: {})'.format(path, path_real) )
			return
		dir_key = path_real.parent().realpath()
		if dir_key not in self.paths_watch:
			log.warn( 'Ignoring event for file outside of watched'
				' set of paths: {} (realpath: {})'.format(path, path_real) )
			return
		for pat in self.paths_watch[dir_key]:
			if fnmatch(bytes(path.basename()), pat): break
		else:
			# log.debug( 'Non-matched path in one of'
			# 	' the watched dirs: {} (realpath: {})'.format(path, path_real) )
			return

		## Get last position
		if self.paths_pos.get(path_real) is not None:
			pos, size, data = self.paths_pos[path_real]
			if self.file_end_check(path_real, pos, size=size, data=data):
				log.debug(( 'Event (mask: {}) for unchanged'
					' path: {}, ignoring' ).format(inotify.humanReadableMask(mask), path))
				return
		else: pos = None

		## Actual processing
		line = self.paths_buff.setdefault(path_real, '')
		with path_real.open('rb') as src:
			if pos:
				src.seek(pos)
				pos = None
			while True:
				buff = src.readline()
				if not buff: # eof
					self.paths_pos[path_real] = self.file_end_mark(path_real, data=line)
				line += buff
				if line.endswith('\n'):
					log.debug('New line (source: {}): {!r}'.format(path, line))
					reactor.callLater(0, self.handle_line, line)
					line = self.paths_buff[path_real] = ''
				else:
					line, self.paths_buff[path_real] = None, line
					break

	@defer.inlineCallbacks
	def handle_line(self, line, repo_lock=defer.DeferredLock()):
		try:
			line = line.decode('utf-8').strip()
			match = re.search(r'(^|\s+)!pq\s+(?P<link>\S+)(\s+::\S+|$)', line)
			if not match:
				# log.debug('Non-patchbot line, ignoring: {}'.format(line))
				defer.returnValue(None)
			link = match.group('link').encode('ascii')
			if not re.search('https?://', link, re.IGNORECASE):
				log.warn('Incorrect non-http link, skipping: {}'.format(link))
				defer.returnValue(None)
		except UnicodeError as err:
			log.warn('Failed to recode line ({!r}): {}'.format(line, err))
			defer.returnValue(None)

		# Grab the patch
		dst_base = '{}.patch'.format(sha1(link).hexdigest())
		dst_path = self.dst_path.child(dst_base)
		if dst_path.exists():
			log.debug( 'Patch already exists'
				' (file: {}, link: {}), skipping'.format(dst_path, link) )
			defer.returnValue(None)
		try: yield downloadPage(link, dst_path.open('wb'), timeout=60)
		except:
			if dst_path.exists(): dst_path.remove()
			raise

		# Commit into repo and push
		yield repo_lock.acquire()
		try:
			for cmd, check in [
					(['add', dst_base], True),
					(['commit', '-m', 'New patch: {}'.format(link)], False),
					(['push'], True) ]:
				out, err, code = yield getProcessOutputAndValue(
					'/usr/bin/git', cmd, path=self.dst_path.path )
				if check and code:
					log.error('\n'.join([
						'Failed to commit/push new patch into repo',
						'Command: {}'.format(cmd), 'Exit code:  {}'.format(code),
						'Stdout:\n  {}'.format('\n  '.join(out.splitlines())),
						'Stderr:\n  {}'.format('\n  '.join(err.splitlines())) ]))
					break
			else: log.debug('Successfully pushed paste: {}'.format(link))
		finally: repo_lock.release()


if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(
		description='Watch IRC logs from a specified path and download'
			' all the zebrapig patchbot requests to a given dst_path.')
	parser.add_argument('path_mask',
		help='Glob pattern of IRC logs to watch (can be a dir or dir-glob).')
	parser.add_argument('dst_path',
		help='Dir to download all the patches to.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args()

	logging.basicConfig(level=logging.DEBUG
		if optz.debug else logging.WARNING)
	log.PythonLoggingObserver().start()

	for lvl in 'debug', 'info', ('warning', 'warn'), 'error':
		lvl, func = lvl if isinstance(lvl, tuple) else (lvl, lvl)
		assert not getattr(log, lvl, False)
		setattr(log, func, ft.partial( log.msg,
			logLevel=getattr(logging, lvl.upper()) ))

	# Check permissions
	os.listdir(os.path.dirname(optz.path_mask))
	os.listdir(optz.dst_path)

	tailer = PasteGrabber(optz.path_mask, optz.dst_path)

	log.debug('Starting event loop')
	reactor.run()
