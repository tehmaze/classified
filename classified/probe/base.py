# Python imports
import fnmatch
import grp
import logging
import os
import pwd
import re
import stat
import sys

# Project imports
from classified import checksum
from classified.probe import PROBES, IGNORE


class ProbeTracker(type):
    def __new__(cls, name, bases, attrs):
        new = type.__new__(cls, name, bases, attrs)
        if getattr(new, 'name', None) is None:
            PROBES[name.lower()] = new
        else:
            PROBES[new.name] = new
        return new


class Probe(object, metaclass=ProbeTracker):
    default_buffer = sys.stdout
    target = ()                     # default list of target mime types
    format = None                   # default format string for reporting
    name = None

    def __init__(self, config, report, buffer=None):
        self.config = config
        self.report = report
        self.name = self.name or self.__class__.__name__.lower()

        # Lookup algorithm for doing checks
        self.algorithm = self.config.getdefault('clean:%s' % self.name,
            'algorithm', self.config.getdefault('clean', 'algorithm', 'sha1')
        )

        if buffer is None:
            self.buffer = self.default_buffer
        else:
            self.buffer = buffer

        # See if the ignores are already parsed
        if self.name not in IGNORE:
            IGNORE[self.name] = dict(name=[], hash=[])

            # Ignored hashes
            try:
                ignore_hash = self.config.getmulti('clean:%s' % self.name,
                    'ignore_hash')
                IGNORE[self.name]['hash'] = ignore_hash
            except (self.config.NoOptionError, self.config.NoSectionError):
                IGNORE[self.name]['hash'] = []

            # Ignored names
            try:
                ignore_name = self.config.getmulti('clean:%s' % self.name,
                    'ignore_name')
                IGNORE[self.name]['name'] = [re.compile(fnmatch.translate(pattern)) for pattern in ignore_name]
            except (self.config.NoOptionError, self.config.NoSectionError):
                IGNORE[self.name]['name'] = []

            # Ignored repos
            try:
                ignore_repo = self.config.getmulti('clean:%s' % self.name,
                    'ignore_repo')
                IGNORE[self.name]['repo'] = []
                for ignore in ignore_repo:
                    repo_type, pattern = ignore.split(':', 1)
                    IGNORE[self.name]['repo'].append((
                        repo_type, re.compile(fnmatch.translate(pattern))
                    ))
            except (self.config.NoOptionError, self.config.NoSectionError):
                IGNORE[self.name]['repo'] = []

    def __unicode__(self):
        return self.name

    def can_probe(self, item):
        '''
        Tests if this probe can be ran against the given item.
        '''
        for hook in (self.ignore_name, self.ignore_repo):
            if hook(item):
                logging.debug('ignoring %r in %s: in %s' % (
                    item, self.name, hook.__name__
                ))
                return False

        # We're good, file is not ignored
        return True

    def ignore_hash(self, item, **kwargs):
        '''
        Check if the match is to be ignored, based on hash. This mechanism is
        used to filter out errors and false positives.
        '''
        context = self.config.getdefault('clean:%s' % self.name, 'context',
            self.config.getdefault('clean', 'context', 'line')
        )

        # Calculate checksum using the selected algorith, and check if it is in
        # the ignore list for this probe
        hashing = checksum.new(self.algorithm)
        if context == 'file':
            for line in item.open('rb'):
                hashing.update(line)

        elif context == 'line':
            try:
                if isinstance(kwargs['raw'], str):
                    hashing.update(kwargs['raw'].encode('utf-8'))
                else:
                    hashing.update(kwargs['raw'])
            except KeyError:
                # The reported item has no "raw" format, therefor we can not
                # provide a line-based hash
                return None, False

        elif context == 'format':
            format = self.config.get('clean:%s' % self.name, 'format')
            hashing.update(format.format(**kwargs))

        else:
            raise TypeError('Probe %s does not support %s context' % \
                (self.name, context))

        digest = hashing.hexdigest()
        if digest in IGNORE[self.name]['hash']:
            logging.debug('ignoring %r in %s: %s' % (item, self.name, digest))
            return digest, True
        else:
            logging.debug('allowing %r in %s: %s' % (item, self.name, digest))
            return digest, False

    def ignore_name(self, item):
        '''
        Check if the full path is to be ignored by this type of probe.
        '''
        for pattern in IGNORE[self.name]['name']:
            if pattern.match(str(item)):
                return True
        return False

    def ignore_repo(self, item):
        '''
        Check if the full path is to be ignored by this type of probe.
        '''
        if item.repository.type is None:
            return False

        for repository_type, pattern in IGNORE[self.name]['repo']:
            if repository_type not in (item.repository.type, 'any'):
                continue
            if pattern.match(str(item)):
                return True

        return False

    def probe(self, item):
        raise NotImplementedError

    def record(self, item, **kwargs):
        # Check if we can/may report this item
        digest, ignore = self.ignore_hash(item, **kwargs)
        if ignore:
            return

        # Exend kwargs
        kwargs['hash'] = digest
        kwargs['filename'] = str(item)
        kwargs['filename_relative'] = str(item).replace(os.getcwd(), '.')

        # Find out who owns the file
        info = item.stat()
        kwargs['uid'] = info[stat.ST_UID]
        kwargs['gid'] = info[stat.ST_GID]
        try:
            kwargs['username'] = pwd.getpwuid(kwargs['uid'])[0]
        except KeyError:
            kwargs['username'] = str(kwargs['uid'])
        try:
            kwargs['group'] = grp.getgrgid(kwargs['gid'])[0]
        except KeyError:
            kwargs['group'] = str(kwargs['gid'])

        # Send findings to reporting engine
        self.report.report(self, item, **kwargs)


def isdigit(x):
    if isinstance(x, str):
        return x.isdigit()
    return ord('0') <= x and x <= ord('9')
