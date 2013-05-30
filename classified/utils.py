from collections import defaultdict
from itertools import chain


def flatten(iterable):
    return list(chain.from_iterable(iterable))


def leaders(iterable, top=10):
    counters = defaultdict(int)
    for item in iterable:
        counters[item] += 1

    return sorted(counters.items(), reverse=True, key=lambda tup: tup[1])[:top]
