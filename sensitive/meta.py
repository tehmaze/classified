# Python imports
import os
import sys
import time

# Third party imports
try:
    import magic
except ImportError:
    magic = None  # pyflakes.ignore
    import warnings
    warnings.warn('Could not import required python-magic module')

# Project imports (platform dependant)
if sys.platform == 'linux2':
    from sensitive.platform.linux import get_filesystems
elif sys.platform == 'darwin':
    from sensitive.platform.darwin import get_filesystems  # pyflakes.ignore
else:
    raise NotImplementedError('Not compatible with platform %s' % sys.platform)


def get_filesystem(path, filesystems=[]):
    '''
    Get the filesystem of a given path.
    '''
    path = os.path.abspath(path)
    filesystems = filesystems or get_filesystems()
    filesystems_match = []
    for fs in filesystems:
        if path.startswith(fs['mount']):
            filesystems_match.append(fs)

    # Sort by longest matching path
    filesystems_match.sort(
        lambda a, b: cmp(len(b['mount']), len(a['mount']))
    )
    return filesystems_match[0]


class Path(object):
    def __init__(self, path):
        self.path = os.path.abspath(path)

        # Normalise path
        if os.path.islink(self.path):
            result = os.readlink(self.path)
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
        return '<File %s mimetype=%s fs-type=%s>' % (self.path, self.mimetype,
            self.mount.fs['type'])

    @property
    def mimetype(self):
        if not hasattr(self, '_mimetype'):
            try:
                self._mimetype = magic.from_file(self.path, mime=True)
            except AttributeError:  # No magic module available
                self._mimetype = None
            except IOError:
                self._mimetype = None
        return self._mimetype

    @property
    def mount(self):
        if not hasattr(self, '_mount'):
            self._mount = Mount(self.path)
        return self._mount


class Mount(Path):
    def __init__(self, path):
        super(Mount, self).__init__(path)
        self.fs = self._detect_fs()

    def _detect_fs(self):
        if not hasattr(Mount, '_fs_cache') or \
                Mount._fs_cache_timeout < time.time():
            setattr(Mount, '_fs_cache', list(get_filesystems()))
            setattr(Mount, '_fs_cache_timeout', time.time() + 60)

        return get_filesystem(str(self), Mount._fs_cache)


if __name__ == '__main__':
    path = File(os.path.expanduser('~'))
    print repr(path)