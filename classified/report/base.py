# Project imports
from classified.report import REPORT


class ReportTracker(type):
    def __new__(cls, name, bases, attrs):
        new = type.__new__(cls, name, bases, attrs)
        if getattr(new, 'name', None) is None:
            REPORT[name.lower()] = new
        else:
            REPORT[new.name] = new
        return new


class Report(object):
    __metaclass__ = ReportTracker

    def __init__(self, config, option):
        self.config = config
        self.option = option
        self.setup()

    def setup(self):
        pass

    def report(self, probe, item, **kwargs):
        raise NotImplementedError

    def render(self):
        raise NotImplementedError

    # Alias
    __call__ = report
