# Python imports
import grp
import os
import pwd
import stat

# Project imports
from sensitive.probe.base import Probe


class SSH(Probe):
    format = '{filename}[{line:d}]: {key_info} {key_type} {username}'
    
    def probe(self, item):
        with open(str(item), 'rb') as handle:
            key = False
            key_info = ['plaintext']
            key_type = None
            
            line = ''
            lineno = 0
            while line == '':
                line = handle.readline().strip()
                lineno += 1
            
            if '-----BEGIN RSA PRIVATE KEY-----' in line:
                key = 'RSA private key'
                key_type = 'rsa'
            elif 'SSH PRIVATE KEY FILE FORMAT 1' in line:
                key = 'RSA1 private key'
                key_type = 'rsa1'
            elif '-----BEGIN DSA PRIVATE KEY-----' in line:
                key = 'DSA private key'
                key_type = 'dsa'
            elif '-----BEGIN EC PRIVATE KEY-----' in line:
                key = 'ECDSA private key'
                key_type = 'ecdsa'
            else:
                # No SSH private key was found
                return
            
            line = ''
            while line == '':
                line = handle.readline().strip()

            if line.startswith('Proc-Type:') and 'ENCRYPTED' in line:
                key_info = ['encrypted']
            
            info = os.stat(str(item))
            mode = info[stat.ST_MODE]
            # Check if file is group or world-readable
            if mode & stat.S_IRGRP or mode & stat.S_IROTH:
                key_info.append('readable')
            else:
                key_info.append('protected')
            
            self.report(str(item),
                line=lineno,
                key=key,
                key_info=' '.join(key_info),
                key_type=key_type,
            )