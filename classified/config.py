# Python imports
from ConfigParser import ConfigParser, Error, NoOptionError, NoSectionError
import os
import re


class Config(ConfigParser):
    Error = Error
    NoOptionError = NoOptionError
    NoSectionError = NoSectionError

    re_padding = re.compile(r'(^[\s\t,]+|[\s\t,]+$)')

    def __init__(self, filename, *args, **kwargs):
        ConfigParser.__init__(self, *args, **kwargs)
        if filename:
            if os.access(filename, os.R_OK):
                self.read([filename])
            else:
                raise IOError('Could not open {} for reading'.format(filename))

    def getdefault(self, section, option, default=None):
        try:
            return self.get(section, option)
        except (NoOptionError, NoSectionError):
            return default

    def getlist(self, section, option, sep=','):
        value = self.get(section, option)
        return map(lambda item: item.strip(), value.split(sep))

    def getmulti(self, section, option, strip_comments=True):
        multi = []
        for item in self.get(section, option).splitlines():
            # Remove comments, if enabled
            if strip_comments:
                item = item.rsplit(' #', 1)[0]

            # Clean up padding
            item = self.re_padding.sub('', item)
            multi.append(item)
        return multi
