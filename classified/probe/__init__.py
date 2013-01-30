# Python imports
import glob
import imp
import inspect
import os
import sys


PROBES = dict()


def get_probe(name):
    try:
        return PROBES[name]
    except KeyError:
        raise NotImplementedError