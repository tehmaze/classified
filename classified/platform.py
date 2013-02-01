# Python imports
import os

# Project imports
from classified._platform import get_filesystems


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
