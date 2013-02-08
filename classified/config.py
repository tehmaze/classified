# Python imports
from ConfigParser import ConfigParser, NoOptionError, NoSectionError
import re


class Config(ConfigParser):
    NoOptionError = NoOptionError
    NoSectionError = NoSectionError

    def __init__(self, filename, *args, **kwargs):
        ConfigParser.__init__(self, *args, **kwargs)
        self.read([filename])

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
        for item in self.getlist(section, option, '\n'):
            if strip_comments:
                item = item.split(' #', 1)[0].rstrip()
            multi.append(item)
        return multi
