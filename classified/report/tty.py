import datetime
import os
from classified.report.html import HTMLReport


class TTYReport(HTMLReport):
    name = 'tty'
    template = 'report/full.tty'

    def setup(self):
        # Setup template environment
        self.setup_env()

    def render(self):
        self.entries['user'] = os.environ.get('USER', 'no-reply')
        self.entries['time']['finish'] = datetime.datetime.now()

        # Compile MIME message
        print self.template.render(**self.entries)
