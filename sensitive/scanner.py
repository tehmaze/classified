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
        self.mount_exclude = self.config.getlist('scanner', 'mount_exclude')

        # Max traversal depths
        self.mindepth = int(self.config.getdefault('scanner', 'mindepth', -1))
        self.maxdepth = int(self.config.getdefault('scanner', 'maxdepth', -1))
        
        # Import probes
        for option in self.config.getlist('scanner', 'probe_include'):
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
            if item.mimetype is None:
                continue
            elif item.mount.fs['type'] in self.mount_exclude:
                logging.info('skipping %s: excluded fs type %s' % (item,
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
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                yield File(full)

            if self.maxdepth >= 0 and (depth + 1) >= self.maxdepth:
                continue

            for dirname in dirnames:
                full = os.path.join(dirpath, dirname)
                for item in self.walk(full, depth + 1):
                    yield item
