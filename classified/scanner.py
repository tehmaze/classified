# Python imports
import fnmatch
import logging
import re
import traceback
import StringIO

# Project imports
from classified.incremental import Incremental
from classified.meta import Path, CorruptionError
from classified.probe import get_probe
#from classified.probe.all import *


class Scanner(object):
    def __init__(self, config):
        self.config = config

        # Excluded file system types
        try:
            self.exclude_dirs = self.config.getmulti('scanner', 'exclude_dirs')
        except self.config.NoOptionError:
            self.exclude_dirs = []
        try:
            self.exclude_fs = self.config.getmulti('scanner', 'exclude_fs')
        except self.config.NoOptionError:
            self.exclude_fs = []
        try:
            self.exclude_link = self.config.getboolean('scanner', 'exclude_link')
        except self.config.NoOptionError:
            self.exclude_link = True
        try:
            self.exclude_type = self.config.getmulti('scanner', 'exclude_type')
        except self.config.NoOptionError:
            self.exclude_type = []

        # Max traversal depths
        self.mindepth = int(self.config.getdefault('scanner', 'mindepth', -1))
        self.maxdepth = int(self.config.getdefault('scanner', 'maxdepth', -1))

        # Deflation of archives enabled?
        self.deflate = self.config.getboolean('scanner', 'deflate')

        # Incremental enabled?
        try:
            if self.config.getboolean('scanner', 'incremental'):
                self.incremental = Incremental(self.config)
            else:
                self.incremental = False
        except self.config.NoOptionError:
            self.incremental = False

        # Import probes
        for option in self.config.getlist('scanner', 'include_probe'):
            try:
                __import__('classified.probe.%s' % option)
            except ImportError, e:
                raise TypeError('Invalid probe %s enabled: %s' % (option,
                    str(e)))

        # Setup probes
        self.probes = {}
        for option in self.config.options('probe'):
            pattern = re.compile(fnmatch.translate(option))
            self.probes[pattern] = self.config.getlist('probe', option)

    def probe(self, item, name):
        logging.debug('probe %s on %r' % (name, item))
        try:
            probe = get_probe(name)(self.config)
            if probe.can_probe(item):
                probe.probe(item)
        except NotImplementedError:
            logging.warning('could not start probe %s: not implemented' % name)
        except Exception, error:
            logging.error('probe %s on %r failed: %s' % (name, item, error))
            buffer = StringIO.StringIO()
            traceback.print_exc(file=buffer)
            for line in buffer.getvalue().splitlines():
                logging.debug(line)

    def scan(self, path):
        deflate = self.config.getboolean('scanner', 'deflate')
        try:
            deflate_limit = self.config.getint('scanner', 'deflate_limit')
        except self.config.NoOptionError:
            deflate_limit = 0

        for item in Path(path).walk(deflate=deflate, deflate_limit=deflate_limit):
            if item is None:
                continue

            # No readable file? Skip
            if not item.readable:
                logging.debug('skipping %s: no readable content' % item)
                continue

            # No mime type? Skip
            elif item.mimetype is None:
                logging.debug('skipping %s: no mimetype' % item)
                continue

            # Mime type exclusions
            elif item.mimetype in self.exclude_type:
                logging.debug('skipping %s: mimetype %s excluded' % (item,
                    item.mimetype))
                continue

            # File system type exclusions
            elif item.mount.fs['type'] in self.exclude_fs:
                logging.info('skipping %s: excluded fs %s' % (item,
                    item.mount.fs['type']))
                continue

            elif self.incremental and item in self.incremental:
                logging.debug('skipping %s: file in incremental cache' % item)
                continue

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
