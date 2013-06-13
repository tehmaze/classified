# Python imports
from collections import defaultdict
import datetime
import socket
import sys

# Project imports
from classified.report.base import Report


class HTMLReport(Report):
    name = 'html'

    def setup(self):
        if not self.option.output:
            print >>sys.stderr, 'Please supply an output file with --output'
            sys.exit(1)

        # Setup template environment
        self.setup_env()

    def setup_env(self):
        # Load Jinja2
        from jinja2 import Environment, PackageLoader

        # Load template file
        self.env = Environment(loader=PackageLoader('classified', 'template'))
        self.filename = self.config.get('report:{}'.format(self.name),
                                        'template')
        self.template = self.env.get_template(self.filename)

        # Collected entries
        self.entries = dict(
            fqdn=socket.getfqdn(),
            hostname=socket.gethostname(),
            time=dict(start=datetime.datetime.now(), finish=None),
            probe=defaultdict(list),
            filename=defaultdict(int),
            username=defaultdict(int),
        )


    def report(self, probe, item, **kwargs):
        self.entries['probe'][probe].append((item, kwargs))
        self.entries['filename'][str(item)] += 1
        if 'username' in kwargs:
            self.entries['username'][kwargs['username']] += 1
        elif 'uid' in kwargs:
            self.entries['username'][kwargs['uid']] += 1

    def render(self):
        if self.option.output == '-':
            fp = sys.stdout
        else:
            fp = open(self.option.output, 'w')

        self.entries['time']['finish'] = datetime.datetime.now()
        fp.write(self.template.render(**self.entries))
