#!/usr/bin/env python

import six
import bs4 as BeautifulSoup
from .DOMImplementation import DOMImplementation

def getDOMImplementation(dom = None, **kwds):
    return DOMImplementation(dom if dom else BeautifulSoup.BeautifulSoup(), **kwds)
    
def parseString(html, **kwds):
    return DOMImplementation(BeautifulSoup.BeautifulSoup(html, "html.parser"), **kwds)
    
def parse(_file, **kwds):
    if isinstance(_file, six.string_types):
        with open(_file, 'r') as f:
            return parseString(f.read())
    
    return parseString(_file.read(), **kwds)
