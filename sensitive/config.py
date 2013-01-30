# Python imports
from ConfigParser import ConfigParser, NoOptionError, NoSectionError


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
