# Python imports
import glob
import imp
import inspect
import os
import sys


# Probe lookup map
PROBES = dict()
# Probe lookup map for ignores
IGNORE = dict()


def get_probe(name):
    try:
        return PROBES[name]
    except KeyError:
        raise NotImplementedError
