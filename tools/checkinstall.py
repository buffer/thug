#!/usr/bin/env python
import sys
print ("Checking proper Thug installation...")
try:
    import bs4
    import cffi
    import chardet
    import cssutils
    import decorator
    import future
    import html5lib
    import jsbeautifier
    import lxml
    import magic
    import networkx
    import pefile
    import pika
    import pycparser
    import pygraphviz
    import pylibemu
    import pymongo
    import pyparsing
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

try:
    from androguard.core import androconf
    from androguard.core.bytecodes import apk
    from androguard.core.bytecodes import dvm
    from androguard.core.analysis import analysis
except ImportError:
    print("Androguard not found - APK analysis disabled")
    print ("All requirements for Thug except Androguard are satisfied.")
    sys.exit()

print ("All requirements for Thug are satisfied.")
