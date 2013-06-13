# Python imports
import os
import re


# Project imports
from classified.probe.base import Probe


class Password(Probe):
    default_pattern = r'\bpass(?:|wd|word)\b[ \s\t=:]+(?P<password>.*)'
    format = '{filename_relative}[{line}]: {type} {text_masked}'

    def __init__(self, config, *args, **kwargs):
        super(Password, self).__init__(config, *args, **kwargs)

        try:
            pattern = self.config.get('probe:password', 'pattern')
        except self.config.NoOptionError:
            pattern = self.default_pattern
        self.re_password = re.compile(pattern)

    def probe(self, item):
        filename = str(item)
        basename = os.path.basename(filename)

        item.open()
        try:
            if 'pgpass' in basename:
                self.probe_pgpass(item)

            # Scan for passwords heuristically in any case            
            line = 0
            for text in item:
                line += 1
                for password in self.re_password.findall(text):
                    if password == '':
                        continue

                    self.record(item,
                        raw=text,
                        type='password',
                        line=line,
                        text=text.rstrip(),
                        text_masked=text.rstrip().replace(password, '********'),
                        password=password,
                        password_masked='********',
                    )
        finally:
            item.close()

    def probe_pgpass(self, item):
        line = 0
        for text in item:
            line += 1
            part = text.split(':')
            if len(part) == 5 and part[4]:
                self.record(item,
                    raw=text,
                    type='pgpass',
                    line=line,
                    text=text.rstrip(),
                    text_masked=':'.join(part[:4] + ['********']),
                    password=part[4],
                    password_masked='********',
                )

        item.seek(0)  # reset file handle
