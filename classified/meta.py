# Python imports
import bz2
import gzip
import logging
import os
import posix
import stat
import tarfile
import time
import zipfile
import warnings

# Third party imports
try:
    import lzma
except ImportError:
    try:
        import backports.lzma as lzma
    except ImportError:
        lzma = None
        warnings.warn('Could not import optional lzma module')
try:
    import rarfile
except ImportError:
    rarfile = None
    warnings.warn('Could not import optional rarfile module')

# Project imports
try:
    from classified import magic
except ImportError:
    magic = None  # pyflakes.ignore
    warnings.warn('Could not import required python-magic module')
    raise
# Project imports (platform dependant)
from classified.platform import get_filesystem, get_filesystems


class CorruptionError(ValueError):
    pass


class Path(object):
    def __init__(self, path, parent=None):
        self.path = os.path.abspath(path)
        self.parent = parent

        # Flags used by recursor
        self.walkable = True
        self.readable = False

        # Normalise path
        if os.path.islink(self.path):
            result = os.readlink(self.path)
            if result.startswith(os.sep):
                self.path = os.path.abspath(result)
            else:
                self.path = os.path.abspath(os.path.join(
                    os.path.dirname(self.path), result
                ))

        # Proxy attributes
        for attr in dir(self.path):
            if attr.startswith('_'):
                continue

            elif hasattr(self, attr):
                continue

            else:
                setattr(self, attr, getattr(self.path, attr))

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.path)

    def __str__(self):
        return self.path

    def probe(cls, path):
        try:
            fileinfo = os.stat(path)
            filemode = fileinfo[stat.ST_MODE]
        except (IOError, OSError):
            return False
        else:
            return stat.S_ISDIR(filemode)

    probe = classmethod(probe)

    def walk(self, recurse=True, depth=0, max_depth=10,
             deflate=True, deflate_limit=0):

        logging.debug('%s depth %d/%d' % (self.path, depth, max_depth))

        for item in self.walk_tree(deflate, deflate_limit):
            if item is None:
                continue

            else:
                yield item

                if recurse and (max_depth and depth >= max_depth):
                    logging.warning('%s max recursion depth' % (self.path,))
                    continue

                if recurse and item.walkable:
                    try:
                        for sub in item.walk(depth=depth + 1, max_depth=max_depth):
                            yield sub
                    except (IOError, OSError), error:
                        logging.error('%s error %s' % (self.path, str(error)))

    def walk_tree(self, deflate, deflate_limit):
        if os.access(self.path, os.R_OK):
            for item in os.listdir(self.path):
                full = os.path.join(self.path, item)
                if Path.probe(full):
                    yield Path(full, parent=self)
                else:
                    mount_hint = getattr(self, '_mount', None)
                    yield File.maybe(
                        full,
                        deflate_if_archive=deflate,
                        deflate_limit=deflate_limit,
                        mount_hint=mount_hint,
                        parent=self,
                    )
        else:
            logging.error('%s not accessible, skipping' % (self.path,))


class Repository(Path):
    supported_types = {
        # GNU Arch
        'arch': (
            ('file', os.path.join('{arch}', '.arch-project-tree')),
        ),
        # Bazaar
        'bzr': (
            ('path', os.path.join('.bzr', 'repository')),
        ),
        # Concurrent Versions System
        'cvs': (
            ('path', 'CVS'),
            ('path', 'CVSROOT'),
        ),
        # DARCS
        'darcs': (
            ('path', os.path.join('_darcs', 'pristine.hashed')),
        ),
        # Git SCM
        'git': (
            ('path', os.path.join('.git', 'objects')),      # repository
            ('path', os.path.join('refs', 'heads')),        # bare repository
        ),
        # Mercurial
        'hg': (
            ('path', os.path.join('.hg', 'store')),
        ),
        # Monotone
        'monotone': (
            ('file', os.path.join('_MTN', 'format')),
        ),
        # Revision Control System
        'rcs': (
            ('path', 'RCS'),
        ),
        # Subversion (SVN)
        'svn': (
            ('file', os.path.join('.svn', 'format')),   # repository (checkout)
            ('path', os.path.join('db', 'revs')),       # repository
        ),
    }
    type_cache = {}

    def __init__(self, path):
        super(Repository, self).__init__(path)
        self.type = self._detect_type()

    def _detect_type(self):
        node = self
        while node is not None:
            # This only works for directories
            if not isinstance(node, Path):
                node = node.parent or Path(os.path.dirname(node.path))
            try:
                return Repository.type_cache[node.path]
            except KeyError:
                repository_type = self._detect_type_path(node.path)

            if repository_type is None:
                if node.parent is None:
                    path = os.path.dirname(node.path)
                    # Stop iterating if we hit the file system root
                    if path != node.path and os.path.isdir(path):
                        node = Path(path)
                    else:
                        node = None
                else:
                    node = node.parent
            else:
                Repository.type_cache[node.path] = repository_type
                return repository_type

    def _detect_type_path(self, path):
        for vendor, probes in self.supported_types.iteritems():
            for filetype, filename in probes:
                filepath = os.path.join(path, filename)
                try:
                    fileinfo = os.stat(filepath)
                    filemode = fileinfo[stat.ST_MODE]
                except (IOError, OSError):
                    continue

                # Common types
                if filetype == 'path' and stat.S_ISDIR(filemode):
                    return vendor
                if filetype == 'file' and stat.S_ISREG(filemode):
                    return vendor
                # Less common types
                if filetype == 'char' and stat.S_ISCHR(filemode):
                    return vendor
                if filetype == 'fifo' and stat.S_ISFIFO(filemode):
                    return vendor
                if filetype == 'link' and stat.S_ISLNK(filemode):
                    return vendor
                if filetype == 'sock' and stat.S_ISSOCK(filemode):
                    return vendor

        # It's not a repository (that we know of)
        return None


class File(Path):
    Corrupt = CorruptionError

    def __init__(self, path, parent):
        super(File, self).__init__(path, parent=parent)

        self.handle = None

        # Clone?
        if isinstance(path, File):
            self.walkable = path.walkable
            self.readable = path.readable
            self.mimetype = path.mimetype

        else:
            # Flags used by recursor
            self.walkable = False
            self.readable = True

    def __repr__(self):
        return '<%s %s mime-type=%s fs-type=%s repository-type=%s>' % (
            self.__class__.__name__,
            self.path,
            self.mimetype or 'unknown',
            self.mount.fs['type'],
            self.repository.type
        )

    # Method that does archive detection
    def maybe(path, deflate_if_archive=True, deflate_limit=0, mount_hint=None, parent=None):
        instance = File(path, parent=parent)
        if deflate_if_archive and instance.mimetype in Archive.supported_mimetypes:
            if deflate_limit > 0 and instance.size > deflate_limit:
                logging.warning('skipped archive %s: too big (%s > %s)' % \
                    (instance, instance.size, deflate_limit))
                return instance

            try:
                instance = Archive(instance, mount_hint, parent=parent)
                logging.debug('opened archive %s: %s' % (instance,
                    instance.mimetype))
            except CorruptionError, e:
                logging.warn('failed to inspect archive %s: %s' % (instance,
                    e))

        return instance

    maybe = staticmethod(maybe)

    # Low-level file like methods

    def __iter__(self):
        return iter(self.handle)

    def close(self):
        self.handle.close()
        return self

    def read(self, size=None):
        try:
            return self.handle.read(size)
        except (EOFError, IOError):
            raise self.__class__.Corrupt(self.path)

    def open(self, mode='r'):
        self.handle = open(self.path, mode)
        return self

    def seek(self, offset, whence=0):
        self.handle.seek(offset, whence)
        return self

    def stat(self):
        return os.stat(self.path)

    def tell(self):
        return self.handle.tell()

    def readline(self):
        return self.handle.readline()

    def readlines(self):
        return self.handle.readlines()

    # Dynamic properties

    def mimetype_get(self):
        if not hasattr(self, '_mimetype'):
            try:
                self._mimetype = magic.from_file(self.path, mime=True)
            except NameError:
                self._mimetype = None
        return self._mimetype

    def mimetype_set(self, mimetype):
        self._mimetype = mimetype

    mimetype = property(mimetype_get, mimetype_set)

    def mount_get(self):
        if not hasattr(self, '_mount'):
            self._mount = Mount(self.path)
        return self._mount

    def mount_set(self, mount):
        self._mount = mount

    mount = property(mount_get, mount_set)

    def mtime_get(self):
        return self.stat()[stat.ST_MTIME]

    mtime = property(mtime_get)

    def repository_get(self):
        if not hasattr(self, '_repository'):
            self._repository = Repository(self.path)
        return self._repository

    repository = property(repository_get)

    def size_get(self):
        return self.stat()[stat.ST_SIZE]

    size = property(size_get)


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


class Archive(File):
    supported_mimetypes = [
        'application/x-bzip2',
        'application/x-gzip',
        'application/x-tar',
        'application/zip',
    ]

    def __init__(self, path, mount_hint=None, parent=None):
        super(Archive, self).__init__(path, parent=parent)

        # Flags used by recursor
        self.walkable = True
        self.readable = False

        if not mount_hint is None:
            self._mount = mount_hint

        base, mimetype = self.mimetype.split('/', 1)
        if mimetype in ['x-bzip2', 'x-gzip', 'x-xz']:
            # Try to see if this is a compressed file, or a compressed archive
            self.bundle = tarfile.is_tarfile(self.path)
            if self.bundle:
                self.recursor = self._recursor_tar
                self.handle = tarfile.open(self.path)
            else:
                self.recursor = self._recursor_compressed

                if mimetype == 'x-bzip2':
                    self.handle = bz2.BZ2File(self.path)
                elif mimetype == 'x-gzip':
                    self.handle = gzip.open(self.path)
                elif mimetype == 'x-xz':
                    # Both lzma, backports.lzma and pyliblzma provide the lzma
                    # module for importing, yet they have a different API
                    if hasattr(lzma, 'open'):
                        self.handle = lzma.open(self.path)
                    elif hasattr(lzma, 'LZMAFile'):  # pyliblzma
                        self.handle = lzma.LZMAFile(self.path, mode='r')

                # Override mimetype by the mimetype of the compressed file
                self.mimetype = magic.from_buffer(self.read(1024), mime=True)

        elif mimetype == 'x-rar' and rarfile is not None:
            try:
                self.handle = rarfile.RarFile(self.path)
            except OSError:
                warnings.userwarning('Failed to open rar archive, have you '
                                     'installed the unrar binary?')
            self.recursor = self._recursor_rar

        elif mimetype == 'x-tar':
            self.handle = tarfile.open(self.path)
            self.recursor = self._recursor_tar

        elif mimetype == 'zip':
            self.recursor = self._recursor_zip
            self.handle = zipfile.ZipFile(self.path)

    def _recursor_compressed(self, depth, max_depth):
        yield ArchiveFile(self.path, self)

    def _recursor_rar(self, depth, max_depth):
        for item in self.handle.infolist():
            size = len(item.filename.split(os.sep))
            if (depth + size - 1) >= max_depth:
                continue
            full = os.path.join(self.path, item.filename)
            try:
                yield ArchiveFile(full, self)
            except KeyError:  # File not in archive
                pass

    def _recursor_tar(self, depth, max_depth):
        for item in self.handle.getmembers():
            size = len(item.name.split(os.sep))
            if (depth + size - 1) >= max_depth:
                continue
            full = os.path.join(self.path, item.name)
            if item.type == tarfile.REGTYPE:
                try:
                    yield ArchiveFile(full, self)
                except KeyError:  # File not in archive
                    pass

    def _recursor_zip(self, depth, max_depth):
        for item in self.handle.infolist():
            size = len(item.filename.split(os.sep))
            if (depth + size - 1) >= max_depth:
                continue
            full = os.path.join(self.path, item.filename)
            try:
                yield ArchiveFile(full, self)
            except KeyError:  # File not in archive
                pass

    def walk(self, depth=0, max_depth=10):
        if self.walkable and (not max_depth or depth < max_depth):
            for item in self.recursor(depth=depth+1, max_depth=max_depth):
                yield item


class ArchiveFile(File):
    def __init__(self, path, archive):
        super(ArchiveFile, self).__init__(path, parent=archive)

        # Archive that contains this file
        self.archive = archive

        # Name of this file in the archive
        self.filename = self.path.replace(self.archive.path, '')
        self.filename = self.filename.lstrip(os.sep)

        self.walkable = False

        if rarfile and isinstance(self.archive.handle, rarfile.RarFile):
            self.member = self.archive.handle.getinfo(self.filename)
            self.readable = True

        elif isinstance(self.archive.handle, tarfile.TarFile):
            self.member = self.archive.handle.getmember(self.filename)
            self.readable = self.member.isreg()

        elif isinstance(self.archive.handle, zipfile.ZipFile):
            self.member = self.archive.handle.getinfo(self.filename)
            self.readable = True

    def open(self, mode='r'):
        if 'w' in mode or 'a' in mode:
            raise IOError('Archives are read-only')
        if not self.readable:
            raise IOError('Archive member not readable')

        if isinstance(self.archive.handle, bz2.BZ2File):
            try:
                self.handle = bz2.BZ2File(self.archive.path, mode=mode)
                return self.handle
            except IOError, e:
                raise Archive.Corrupt(self.path)

        elif isinstance(self.archive.handle, gzip.GzipFile):
            try:
                self.handle = gzip.GzipFile(self.archive.path, mode=mode)
                return self.handle
            except IOError, e:
                raise Archive.Corrupt(self.path)

        elif lzma and isinstance(self.archive.handle, lzma.LZMAFile):
            try:
                self.handle = lzma.LZMAFile(self.archive.path, mode=mode)
                return self.handle
            except lzma.LZMAError, e:
                raise Archive.Corrupt(self.path)

        elif rarfile and isinstance(self.archive.handle, rarfile.RarFile):
            mode = mode.replace('b', '')  # not supported in rar files
            try:
                self.handle = self.archive.handle.open(self.filename, mode)
                return self.handle
            except rarfile.Error, e:
                logging.warning(str(e))
                raise Archive.Corrupt(self.path)
            except OSError:
                logging.error('failed to open rar archive, did you install '
                              'the unrar binary?')
                raise Archive.Corrupt(self.path)
            except TypeError, e:
                logging.error('failed to open rar archive, file corrupt? %s'
                              % str(e))
                raise Archive.Corrupt(self.path)

        elif isinstance(self.archive.handle, tarfile.TarFile):
            try:
                self.handle = tarfile.TarFile.fileobject(self.archive.handle,
                    self.member)
                return self.handle
            except tarfile.TarError, e:
                logging.info(str(e))
                raise Archive.Corrupt(self.path)

        elif isinstance(self.archive.handle, zipfile.ZipFile):
            try:
                mode = mode.replace('b', '')  # not supported in zip files
                self.handle = self.archive.handle.open(self.filename, mode)
                return self.handle
            except zipfile.BadZipfile, e:
                logging.warning(str(e))
                raise Archive.Corrupt(self.path)
            except RuntimeError, e:
                error = str(e)
                if 'password required' in error:
                    logging.info(error)
                else:
                    logging.critical(error)
                raise Archive.Corrupt(self.path)

        else:
            raise NotImplementedError('Archive format not supported')

    def stat(self):
        '''
        Provides an interface like ``os.stat()``
        '''
        if isinstance(self.archive.handle, bz2.BZ2File):
            return self.archive.stat()

        elif isinstance(self.archive.handle, gzip.GzipFile):
            return self.archive.stat()

        elif lzma and isinstance(self.archive.handle, lzma.LZMAFile):
            return self.archive.stat()

        elif isinstance(self.archive.handle, tarfile.TarFile):
            return posix.stat_result((
                self.member.mode,
                -1,
                -1,
                -1,
                self.member.uid,
                self.member.gid,
                self.member.size,
                self.member.mtime,
                self.member.mtime,
                self.member.mtime,
            ))

        elif rarfile and isinstance(self.archive.handle, rarfile.RarFile):
            info = self.archive.stat()
            return posix.stat_result((
                info[stat.ST_MODE],
                -1,
                -1,
                -1,
                info[stat.ST_UID],
                info[stat.ST_GID],
                self.member.file_size,
                time.mktime(self.member.date_time + (0, 0, 0)),
                time.mktime(self.member.date_time + (0, 0, 0)),
                time.mktime(self.member.date_time + (0, 0, 0)),
            ))

        elif isinstance(self.archive.handle, zipfile.ZipFile):
            info = self.archive.stat()
            return posix.stat_result((
                info[stat.ST_MODE],
                -1,
                -1,
                -1,
                info[stat.ST_UID],
                info[stat.ST_GID],
                self.member.file_size,
                time.mktime(self.member.date_time + (0, 0, 0)),
                time.mktime(self.member.date_time + (0, 0, 0)),
                time.mktime(self.member.date_time + (0, 0, 0)),
            ))

    def mimetype_get(self):
        if not hasattr(self, '_mimetype'):
            try:
                self.open('rb')
            except CorruptionError:
                self._mimetype = None
            else:
                self._mimetype = magic.from_buffer(self.read(1024), mime=True)
        return self._mimetype

    mimetype = property(mimetype_get)


# Support for these mime types depend on the availability of third party
# modules (or Python 3.x for some)
if lzma is not None:
    Archive.supported_mimetypes.append('application/x-xz')
if rarfile is not None:
    Archive.supported_mimetypes.append('application/x-rar')


if __name__ == '__main__':
    path = File(os.path.expanduser('~'))
    print repr(path)
