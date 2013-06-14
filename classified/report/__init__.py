# Report lookup map
REPORT = dict()


def get_report(name, *args, **kwargs):
    try:
        return REPORT[name](*args, **kwargs)
    except KeyError:
        raise NotImplementedError(name)
