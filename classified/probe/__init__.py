# Probe lookup map
PROBES = dict()
# Probe lookup map for ignores
IGNORE = dict()
# Report counters
REPORT = dict()


def get_probe(name, *args, **kwargs):
    try:
        return PROBES[name](*args, **kwargs)
    except KeyError:
        raise NotImplementedError(name)
