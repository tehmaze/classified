# Python imports
import fnmatch
import logging
import re
import traceback
import StringIO

# Project imports
from classified.meta import Path, CorruptionError
from classified.probe import get_probe
#from classified.probe.all import *


class Scanner(object):
    def __init__(self, config):
        self.config = config

        # Excluded file system types
        try:
            self.exclude_dirs = self.config.getlist('scanner', 'exclude_dirs')
        except self.config.NoOptionError:
            self.exclude_dirs = []
        try:
            self.exclude_fs = self.config.getlist('scanner', 'exclude_fs')
        except self.config.NoOptionError:
            self.exclude_fs = []
        try:
            self.exclude_link = self.config.getboolean('scanner', 'exclude_link')
        except self.config.NoOptionError:
            self.exclude_link = True

        # Max traversal depths
        self.mindepth = int(self.config.getdefault('scanner', 'mindepth', -1))
        self.maxdepth = int(self.config.getdefault('scanner', 'maxdepth', -1))

        # Deflation of archives enabled?
        self.deflate = self.config.getboolean('scanner', 'deflate')

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
        for item in Path(path).walk(deflate):
            if item is None:
                continue

            # No readable file? Skip
            if not item.readable:
                logging.debug('skipping %s: not readable' % item)
                continue

            # No mime type? Skip
            if item.mimetype is None:
                logging.debug('skipping %s: no mimetype' % item)
                continue

            # File system type exclusions
            elif item.mount.fs['type'] in self.exclude_fs:
                logging.info('skipping %s: excluded fs %s' % (item,
                    item.mount.fs['type']))
                continue

            else:
                logging.debug('scanning %r' % item)

            for pattern, probes in self.probes.iteritems():
                if pattern.match(item.mimetype):
                    for probe in probes:
                        try:
                            self.probe(item, probe)
                        except CorruptionError, e:
                            logging.error('probe %s on %s failed: %s' % (probe,
                                item, e))
