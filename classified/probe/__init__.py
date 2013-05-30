# Probe lookup map
PROBES = dict()
# Probe lookup map for ignores
IGNORE = dict()
# Report counters
REPORT = dict()

def get_probe(name):
    try:
        return PROBES[name]
    except KeyError:
        raise NotImplementedError
