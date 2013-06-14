import syslog
from classified.report.base import Report


class SyslogReport(Report):
    name = 'syslog'

    def setup(self):
        # Open syslog
        facility = getattr(syslog, 'LOG_{}'.format(
            self.config.getdefault('report:syslog', 'syslog_facility',
                                   'daemon').upper()
        ))
        syslog.openlog('classified',
                       syslog.LOG_PID,
                       facility)

    def report(self, probe, item, **kwargs):
        formatter = self.config.get('report:syslog', 'format_{}'.format(probe))
        message = formatter.format(**kwargs)
        self.emit(message)

    def emit(self, message):
        syslog.syslog(message)

    def render(self, *args, **kwargs):
        pass  # No rendering step for syslog
