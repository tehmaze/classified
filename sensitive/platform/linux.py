PROC_MOUNTS_HEADER = ('device', 'mount', 'type', 'flags', 'dummy')
PROC_MOUNTS_COLUMN = len(PROC_MOUNTS_HEADER)


def get_filesystems():
    '''
    Get an overview of mounted file systems on Linux.
    '''

    handle = open('/proc/mounts', 'rb')
    for line in handle.readlines():
        yield dict(zip(
            PROC_MOUNTS_HEADER,
            line.split(' ', PROC_MOUNTS_COLUMN)
        ))
