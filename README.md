zebrapig-helpers: misc scripts related to [exherbo linux](http://exherbo.org/) development
--------------------

##### paste_grabber

Inotify watcher for IRC logs' path (or glob pattern) for [zebrapig
patchbot](http://exherbo.org/docs/patchbot.html) "patch queue" ("!pq") requests.

Upon spotting a new request with a paste-link in it, stores it into `dst_path`,
with sha1 of the link as a basename (technically, "${sha1}.patch").

Purpose it to mirror transient and unreliable links to pastebin-like services to
something more permanent. Currently that "more permanent" thing is a
github-mirrored repo,
[exherbo-patches](https://github.com/mk-fg/exherbo-patches).

Requirements: [Twisted
Core](https://pypi.python.org/pypi/Twisted%20Core/12.0.0), [Twisted
Web](https://pypi.python.org/pypi/Twisted%20Web/12.0.0)

Usage:

	usage: paste_grabber.py [-h] [--debug] path_mask dst_path

	Watch IRC logs from a specified path and download all the zebrapig patchbot
	requests to a given dst_path.

	positional arguments:
	  path_mask   Glob pattern of IRC logs to watch (can be a dir or dir-glob).
	  dst_path    Dir to download all the patches to.

	optional arguments:
	  -h, --help  show this help message and exit
	  --debug     Verbose operation mode.
