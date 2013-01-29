# Python imports
import grp
import os
import pwd
import stat

# Project imports
from sensitive.probe import PROBES


class ProbeTracker(type):
    def __new__(cls, name, bases, attrs):
        new = type.__new__(cls, name, bases, attrs)
        if getattr(new, 'name', None) is None:
            PROBES[name.lower()] = new
        else:
            PROBES[new.name] = new
        return new


class Probe(object):
    __metaclass__ = ProbeTracker
    format = None
    name = None

    def __init__(self, config):
        self.config = config
        self.name = self.name or self.__class__.__name__.lower()

    def can_probe(self, item):
        return True

    def probe(self, item):
        raise NotImplementedError
    
    def report(self, filename, **kwargs):
        format = self.config.getdefault('probe:%s' % self.name, 'format',
            self.format) 
        
        kwargs['filename'] = filename
        kwargs['filename_relative'] = filename.replace(os.getcwd(), '.')

        # Find out who owns the file
        info = os.stat(filename)
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
        
        print format.format(**kwargs)