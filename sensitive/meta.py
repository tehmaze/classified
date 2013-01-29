# Python imports
import os

# Third imports
try:
    import magic
except ImportError:
    raise RuntimeWarning('Could not import required python-magic module')


class Path(object):
    def __init__(self, path):
        self.path = os.path.abspath(path)

        # Normalise path
        if os.path.islink(self.path):
            result = os.readlink(self.path)
            print result, os.path.dirname(self.path)
            print os.path.join(os.path.dirname(self.path), result)
            if result.startswith(os.sep):
                self.path = os.path.abspath(result)
            else:
                self.path = os.path.abspath(os.path.join(
                    os.path.dirname(self.path), result
                ))

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.path)

    def __str__(self):
        return self.path


class File(Path):
    def __init__(self, path):
        super(File, self).__init__(path)

    def __repr__(self):
        return '<File %s mimetype=%s>' % (self.path, self.mimetype)

    @property
    def mimetype(self):
        if not hasattr(self, '_mimetype'):
            try:
                self._mimetype = magic.from_file(self.path, mime=True)
            except IOError:
                self._mimetype = None
        return self._mimetype
