# Python imports
import os
import subprocess
import sys
try:
    import win32com.client
except ImportError:
    pass


def get_filesystem(path, filesystems=None):
    '''
    Get the filesystem of a given path.
    '''
    path = os.path.abspath(path)
    if filesystems is None:
        if sys.platform.startswith('linux'):
            filesystems = mounts_linux()
        elif sys.platform in ('darwin', 'freebsd', 'openbsd', 'netbsd'):
            filesystems = mounts_bsd()
        elif sys.platform.startswith('win'):
            filesystems = mounts_windows()
        else:
            filesystems = []

    filesystems_match = []
    for filesystem in filesystems:
        if path.startswith(filesystem['mount']):
            filesystems_match.append(filesystem)

    # Sort by longest matching path
    def _mount(filesystem):
        return filesystem['mount']

    filesystems_match.sort(key=_mount)
    return filesystems_match[0]


def mounts_linux():
    '''List mounted file systems on Linux.'''
    with open('/etc/mtab', 'r') as handle:
        for line in handle:
            part = line.split()
            if len(part) < 6:
                continue
            yield {
                'device': part[0],
                'mount': part[1],
                'type': part[2],
                'options': part[3].split(','),
            }


def mounts_bsd():
    '''List mounted file systems on BSD.'''
    mount = subprocess.run('mount', capture_output=True, check=True)
    for line in mount.stdout.splitlines():
        part = line.decode('ascii').split()
        if len(part) < 4:
            continue
        yield {
            'device': part[0],
            'mount': part[2],
            'type': part[3].lstrip('(').rstrip(','),
        }


def mounts_windows():
    '''List mounted drives on Window.'''
    wmi_service = win32com.client.Dispatch('WbemScripting.SWbemLocator')
    services = wmi_service.ConnectServer('.', "root\\cimv2")
    items = services.ExecQuery('Select * from Win32_LogicalDisk')
    for item in items:
        yield {
            'device': item.DeviceID,
            'mount': item.VolumeName,
        }

if __name__ == '__main__':
    print(get_filesystem('/'))

