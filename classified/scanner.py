# Python imports
import fnmatch
import logging
import os
import re
import datetime
import traceback
import StringIO

# Project imports
from classified.incremental import Incremental
from classified.meta import Path, File, CorruptionError
from classified.probe import get_probe
from classified.report import get_report
import classified.report.all

# Third party imports
try:
    import markdown
except ImportError:
    markdown = None


class Scanner(object):
    def __init__(self, config, option):
        self.config = config
        self.option = option
        self.started = datetime.datetime.now()

        # Excluded file system types
        try:
            self.exclude_dirs = self.config.getmulti('scanner', 'exclude_dirs')
        except self.config.Error:
            self.exclude_dirs = []
        try:
            self.exclude_fs = self.config.getmulti('scanner', 'exclude_fs')
        except self.config.Error:
            self.exclude_fs = []
        try:
            self.exclude_link = self.config.getboolean('scanner', 'exclude_link')
        except self.config.Error:
            self.exclude_link = True
        try:
            self.exclude_type = self.config.getmulti('scanner', 'exclude_type')
        except self.config.Error:
            self.exclude_type = []

        # Max traversal depths
        self.mindepth = int(self.config.getdefault('scanner', 'mindepth', -1))
        self.maxdepth = int(self.config.getdefault('scanner', 'maxdepth', -1))

        # Deflation of archives enabled?
        try:
            self.deflate = self.config.getboolean('scanner', 'deflate')
        except self.config.Error:
            self.deflate = True

        try:
            self.deflate_limit = self.config.getint('scanner', 'deflate_limit')
        except self.config.Error:
            self.deflate_limit = 5

        # Incremental enabled?
        try:
            if self.config.getboolean('scanner', 'incremental'):
                self.incremental = Incremental(self.config)
            else:
                self.incremental = False
        except self.config.Error:
            self.incremental = False

        # Report enabled?
        self.report = get_report(self.option.report_format, self.config,
                                 self.option)

        # Import probes
        probes = set(self.option.probes.split(','))
        try:
            probes.update(self.config.getlist('scanner', 'include_probe'))
        except self.config.Error:
            pass

        if 'all' in probes:
            # Remove it
            probes.remove('all')

            # Auto load all probe module names
            import classified.probe.all
            for probe in classified.probe.all.__all__:
                probe = getattr(classified.probe.all, probe)
                probes.add(probe.__module__.split('.')[-1])

        elif not probes:
            raise TypeError('No probes enabled, check -p')

        modules = {}
        for probe in probes:
            try:
                modules[probe] = __import__('classified.probe.%s' % probe)
            except ImportError, e:
                raise TypeError('Invalid probe %s enabled: %s' % (probe,
                    str(e)))

        # Setup probes
        self.probes = {}
        if self.config.has_section('probe'):
            for option in self.config.options('probe'):
                pattern = re.compile(fnmatch.translate(option))
                self.probes[pattern] = self.config.getlist('probe', option)

        else:
            for name in probes:
                probe = get_probe(name, self.config, self.report)
                for option in probe.target:
                    pattern = re.compile(fnmatch.translate(option))
                    if pattern not in self.probes:
                        self.probes[pattern] = []
                    self.probes[pattern].append(name)

    def probe(self, item, name):
        logging.debug('probe %s on %r' % (name, item))
        try:
            probe = get_probe(name, self.config, self.report)
            if probe.can_probe(item):
                probe.probe(item)
        except NotImplementedError:
            logging.warning('could not start probe %s: not implemented' % name)
        except Exception, error:
            logging.error('probe %s on %r failed: %s' % (name, item, error))
            raise
            buffer = StringIO.StringIO()
            traceback.print_exc(file=buffer)
            for line in buffer.getvalue().splitlines():
                logging.debug(line)

    def scan(self, path, max_depth=10):
        if os.path.isdir(path):
            for item in Path(path).walk(recurse=True,
                                        max_depth=max_depth,
                                        deflate=self.deflate,
                                        deflate_limit=self.deflate_limit):
                self.scan_item(item)

        else:
            self.scan_item(File(path))

    def scan_item(self, item):
        if item is None:
            return

        # No readable file? Skip
        if not item.readable:
            logging.debug('skipping %s: no readable content' % item)
            return

        # No mime type? Skip
        elif item.mimetype is None:
            logging.debug('skipping %s: no mimetype' % item)
            return

        # Mime type exclusions
        elif item.mimetype in self.exclude_type:
            logging.debug('skipping %s: mimetype %s excluded' % (item,
                item.mimetype))
            return

        # File system type exclusions
        elif item.mount.fs['type'] in self.exclude_fs:
            logging.info('skipping %s: excluded fs %s' % (item,
                item.mount.fs['type']))
            return

        elif self.incremental and item in self.incremental:
            logging.debug('skipping %s: file in incremental cache' % item)
            return

        else:
            logging.debug('scanning %r' % item)

        success = True
        for pattern, probes in self.probes.iteritems():
            if pattern.match(item.mimetype):
                for probe in probes:
                    try:
                        self.probe(item, probe)
                    except CorruptionError, e:
                        logging.error('probe %s on %s failed: %s' % (probe,
                            item, e))
                        success = False

        if self.incremental and success:
            self.incremental.add(item)
