import ctypes
libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))

MFSNAMELEN      = 15        # length of fs type name, not inc. null
MFSTYPENAMELEN  = 16        # length of fs type name including null
MAXPATHLEN      = 1024      # length of buffer for returned name


class StructStatfs64(ctypes.Structure):
    # defined in /usr/include/sys/mount.h
    _fields_ = (
        ('f_bsize',       ctypes.c_uint32),
        ('f_iosize',      ctypes.c_int32),
        ('f_blocks',      ctypes.c_uint64),
        ('f_bfree',       ctypes.c_uint64),
        ('f_bavail',      ctypes.c_uint64),
        ('f_files',       ctypes.c_uint64),
        ('f_ffree',       ctypes.c_uint64),
        ('f_fsid',        ctypes.c_int32 * 2),
        ('f_owner',       ctypes.c_int),
        ('f_type',        ctypes.c_uint32),
        ('f_flags',       ctypes.c_uint32),
        ('f_fssubtype',   ctypes.c_uint32),
        ('f_fstypename',  ctypes.c_char * MFSTYPENAMELEN),
        ('f_mnttoname',   ctypes.c_char * MAXPATHLEN),
        ('f_mntfromname', ctypes.c_char * MAXPATHLEN),
        ('f_reserved',    ctypes.c_uint32 * 8),
    )


def cstr(s):
    return s.split('\x00', 1)[0]


def get_filesystems():
    if hasattr(libc, 'getfsstat64'):
        struct = StructStatfs64
    else:
        struct = StructStatfs64  # FIXME

    struct_size = ctypes.sizeof(struct)
    buffer_size = struct_size * 20
    buffer = ctypes.create_string_buffer(buffer_size)

    # MNT_NOWAIT = 2 - don't ask the filesystems, just return cache.
    result = libc.getfsstat64(ctypes.byref(buffer), buffer_size, 2)
    if result == 0:
        raise RuntimeError('getfsstat64() failed')

    for x in xrange(result):
        struct_data = buffer[x * struct_size:(x + 1) * struct_size]
        ref = struct.from_buffer_copy(struct_data)
        yield dict(
            type=cstr(ref.f_fstypename),
            mount=cstr(ref.f_mnttoname),
            device=cstr(ref.f_mntfromname),
        )
