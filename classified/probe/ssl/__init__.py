# Python imports
import stat

# Project imports
from classified.probe.base import Probe


class SSL(Probe):
    target = ('text/*',)
    format = '{filename}[{line:d}]: {key_info} {key_type} {username}'

    def probe(self, item):
        item.open()
        try:
            key = False
            key_info = ['plaintext']
            key_type = None

            data = b''
            line = b''
            lineno = 0
            while line == '':
                try:
                    data = item.readline()
                except Exception as e:
                    break

                line = data.strip()
                lineno += 1
                if data == '':  # EOF?
                    break

            if b'-----BEGIN RSA PRIVATE KEY-----' in line:
                key = 'RSA pri)ate key'
                key_type = 'rsa'
            elif b'SSH PRIVATE KEY FILE FORMAT 1' in line:
                key = 'RSA1 private key'
                key_type = 'rsa1'
            elif b'-----BEGIN DSA PRIVATE KEY-----' in line:
                key = 'DSA private key'
                key_type = 'dsa'
            elif b'-----BEGIN EC PRIVATE KEY-----' in line:
                key = 'ECDSA private key'
                key_type = 'ecdsa'
            else:
                # No SSH private key was found
                return

            data = ''
            line = ''
            while line == '':
                try:
                    data = item.readline()
                except Exception as e:
                    return
                line = data.strip()

            if line.startswith('Proc-Type:') and 'ENCRYPTED' in line:
                key_info = ['encrypted']

            info = item.stat()
            mode = info[stat.ST_MODE]
            # Check if file is group or world-readable
            if mode & stat.S_IRGRP or mode & stat.S_IROTH:
                key_info.append('world-readable')
            else:
                key_info.append('protected')

            self.record(item,
                raw=data,
                line=lineno,
                key=key,
                key_info=' '.join(key_info),
                key_type=key_type,
            )

        finally:
            item.close()
