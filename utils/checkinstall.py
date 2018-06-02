#!/usr/bin/env python
import sys

print("Checking proper Thug installation...")

try:
    import bs4
    import six
    import yara
    import lxml
    import PyV8
    import magic
    import socks
    import ssdeep
    import pefile
    import pymongo
    import rarfile
    import html5lib
    import cchardet
    import cssutils
    import networkx
    import pylibemu
    import requests
    import pygraphviz
    import elasticsearch
    import zope.interface
except ImportError as error:
    print(error)
    print("Make sure to install above packages before running Thug.")
    sys.exit(-1)

print("All requirements for Thug are satisfied.")
