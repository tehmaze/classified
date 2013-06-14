import logging
import sys
from classified.report.syslogger import SyslogReport


class FileReport(SyslogReport):
    name = 'file'
    format = '%(asctime)s %(message)s'

    def setup(self):
        if not self.option.output:
            print >>sys.stderr, 'Please supply an output file with --output'
            sys.exit(1)

        # Setup logger environment
        self.logger = logging.getLogger('classified')
        self.handle = logging.FileHandler(self.option.output)
        formatter = logging.Formatter(
            self.config.getdefault('report:file',
                                   'format',
                                   self.format)
        )
        self.handle.setFormatter(formatter)
        self.logger.addHandler(self.handle)
        self.logger.setLevel(logging.INFO)

    def emit(self, message):
        self.logger.info(message)
