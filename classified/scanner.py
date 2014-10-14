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
        self.exclude_dirs = []
        try:
            self.exclude_dirs = self.config.getmulti('scanner', 'exclude_dirs')
        except self.config.Error:
            pass

        self.exclude_fs = []
        try:
            self.exclude_fs = self.config.getmulti('scanner', 'exclude_fs')
            self.exclude_fs = map(
                lambda pattern: re.compile(fnmatch.translate(pattern)),
                self.exclude_fs
            )
        except self.config.Error:
            pass

        self.exclude_link = True
        try:
            self.exclude_link = self.config.getboolean('scanner', 'exclude_link')
        except self.config.Error:
            pass

        self.exclude_type = []
        try:
            self.exclude_type = self.config.getmulti('scanner', 'exclude_type')
            self.exclude_type = map(
                lambda pattern: re.compile(fnmatch.translate(pattern)),
                self.exclude_type
            )
        except self.config.Error:
            pass

        self.exclude_name = []
        try:
            self.exclude_name = self.config.getmulti('scanner', 'exclude_name')
            self.exclude_name = map(
                lambda pattern: re.compile(fnmatch.translate(pattern)),
                self.exclude_name
            )
        except self.config.Error:
            pass

        self.exclude_repo = {}
        try:
            for item in self.config.getmulti('scanner', 'exclude_repo'):
                try:
                    repository_type, pattern = item.split(':', 1)
                except ValueError:
                    logging.error(
                        '%s: exclude_repo must have format "type:path"' % (
                            self.config.filename,
                        )
                    )
                    raise
                if repository_type not in self.exclude_repo:
                    self.exclude_repo[repository_type] = []
                self.exclude_repo[repository_type].append(re.compile(
                    fnmatch.translate(pattern)
                ))
        except self.config.Error:
            pass

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

    def scan(self, path, max_depth=10):
        if os.path.isdir(path):
            for item in Path(path).walk(
                    recurse=True,
                    max_depth=max_depth,
                    deflate=self.deflate,
                    deflate_limit=self.deflate_limit,
                    checks=(
                        self.test_exclude_fs,
                        self.test_exclude_mimetype,
                        self.test_exclude_name,
                        self.test_exclude_repo,
                    )
                ):
                if self.scan_item(item) is StopIteration:
                    break

        else:
            self.scan_item(File(path))

    def scan_item(self, item):
        if item is None:
            return

        # No readable file? Skip
        if not item.readable:
            logging.debug('skipping %s: no readable content' % item)
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

    def test_exclude_fs(self, item):
        '''Test if the file system type ``item`` is mounted on is excluded.'''
        for test in self.exclude_fs:
            if test.match(item.mount.fs['type']):
                return True
        return False

    def test_exclude_mimetype(self, item):
        '''Test if the mimetype of ``item`` is excluded.'''
        if item is None:
            return True
        else:
            for test in self.exclude_type:
                if test.match(item.mimetype):
                    return True
            return False

    def test_exclude_name(self, item):
        '''Test if the path of ``item`` is excluded.'''
        for test in self.exclude_name:
            if test.match(str(item)):
                return True
        return False

    def test_exclude_repo(self, item):
        '''Test if ``item`` is an excluded repository type.'''
        if item.repository.type is not None:
            for repository_type in (item.repository.type, 'any'):
                if repository_type in self.exclude_repo:
                    for pattern in self.exclude_repo[repository_type]:
                        if pattern.match(str(item)):
                            return True

        return False
