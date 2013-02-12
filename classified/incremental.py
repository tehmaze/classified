# Python imports
try:
    import dbm
except ImportError:
    import anydbm as dbm
import logging

# Project imports
from classified import checksum


class Incremental(object):
    default_algorithm = 'sha1'
    default_blocksize = 16384

    def __init__(self, config):
        self.config = config

        # Local cache
        self.cache = {}

        # Configuration bits
        self.algorithm = self.config.getdefault('incremental', 'algorithm',
            self.default_algorithm)
        self.database = self.config.get('incremental', 'database')
        try:
            self.blocksize = self.config.getint('incremental', 'blocksize')
        except self.config.NoOptionError:
            self.blocksize = self.default_blocksize

        # Open the database in secure mode
        self.db = dbm.open(self.database, 'c', 0600)

        logging.info('only checking incremental changes')
        logging.debug('tracking incremental changes in %s' % self.database)

    def __contains__(self, item):
        if str(item) in self.db:
            old_value = self.db[str(item)]
            new_value = self.cache.get(item, self.checksum(item))
            return old_value == new_value
        else:
            return False

    def add(self, item):
        self.db[str(item)] = self.cache.get(item, self.checksum(item))

    def checksum(self, item):
        if self.algorithm == 'mtime':
            return str(int(item.mtime))

        else:
            method = checksum.new(self.algorithm)
            handle = item.open()
            while True:
                chunk = handle.read(self.blocksize)
                if not chunk:
                    break
                else:
                    method.update(chunk)
            handle.close()

            self.cache[item] = method.hexdigest()
            return self.cache[item]
