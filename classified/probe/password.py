# Python imports
import os
import re


# Project imports
from classified.probe.base import Probe


class Password(Probe):
    re_password = re.compile(r'pass(?:|wd|word)[ \s\t=:]+(?P<password>.*)')
    format = '{filename_relative}[{line}]: {type} {text_masked}'

    def probe(self, item):
        filename = str(item)
        basename = os.path.basename(filename)

        handle = open(str(item), 'rb')
        try:
            if 'pgpass' in basename:
                self.probe_pgpass(item, handle)

            # Scan for passwords heuristically in any case            
            line = 0
            for text in handle:
                line += 1
                for password in self.re_password.findall(text):
                    if password == '':
                        continue

                    self.report(str(item),
                        type='password',
                        line=line,
                        text=text.rstrip(),
                        text_masked=text.rstrip().replace(password, '********'),
                        password=password,
                        password_masked='********',
                    )
        finally:
            handle.close()
    
    def probe_pgpass(self, item, handle):
        line = 0
        for text in handle:
            line += 1
            part = text.split(':')
            if len(part) == 5 and part[4]:
                self.report(str(item),
                    type='pgpass',
                    line=line,
                    text=text.rstrip(),
                    text_masked=':'.join(part[:4] + ['********']),
                    password=part[4],
                    password_masked='********',
                )
        
        handle.seek(0)  # reset file handle