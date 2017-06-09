#!/usr/bin/env python
import sys

print("Checking proper Thug installation...")

try:
    import bs4
    import cchardet
    import cssutils
    import elasticsearch
    import html5lib
    import lxml
    import magic
    import networkx
    import pefile
    import pygraphviz
    import pylibemu
    import pymongo
    import PyV8
    import rarfile
    import requests
    import six
    import socks
    import ssdeep
    import yara
    import zope.interface
except ImportError as error:
    print(error)
    print("Make sure to install above packages before running Thug.")
    sys.exit(-1)

print ("All requirements for Thug are satisfied.")
