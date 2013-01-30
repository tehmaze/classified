# Python imports
import fnmatch
import logging
import os
import re

# Project imports
from sensitive.meta import File, Path
from sensitive.probe import get_probe
#from sensitive.probe.all import *


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

        # Import probes
        for option in self.config.getlist('scanner', 'include_probe'):
            try:
                __import__('sensitive.probe.%s' % option)
            except ImportError:
                raise TypeError('Invalid probe enabled: %s' % option)

        # Setup probes
        self.probes = {}
        for option in self.config.options('probe'):
            pattern = re.compile(fnmatch.translate(option))
            self.probes[pattern] = self.config.getlist('probe', option)

    def probe(self, item, name):
        try:
            probe = get_probe(name)(self.config)
            probe.probe(item)
        except NotImplementedError:
            logging.warning('could not start probe %s: not implemented' % name)

    def scan(self, path):
        for item in self.walk(path):
            filename = str(item)

            # No mime type? Skip
            if item.mimetype is None:
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
                        self.probe(item, probe)

    def walk(self, path=None, depth=0):
        path = os.path.abspath(path or self.path)
        if not os.path.isdir(path):
            raise TypeError('Not a directory: %s' % path)

        elif os.path.basename(path) in self.exclude_fs:
            logging.info('skipping %s: excluded' % path)

        else:
            for item in os.listdir(path):
                full = os.path.join(path, item)
                for leaf in self.walk_item(full, depth):
                    yield leaf

    def walk_item(self, full, depth=0):
        base = os.path.basename(full)

        if os.path.isdir(full):
            if base in self.exclude_dirs:
                logging.info('skipping %s: excluded dir' % full)

            elif self.maxdepth >= 0 and (depth + 1) >= self.maxdepth:
                logging.debug('skipping %s: max depth reachead' % full)

            else:
                # Iterate over child directory
                for leaf in self.walk(full, depth + 1):
                    yield leaf

        elif os.path.islink(full):
            if self.exclude_link:
                logging.info('skipping %s: excluded link' % full)

            else:
                # Treat link target as new item to walk
                target = os.readlink(full)
                for leaf in self.walk_item(target):
                    yield leaf

        else:
            yield File(full)
