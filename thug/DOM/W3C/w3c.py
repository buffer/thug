#!/usr/bin/env python

import six
import bs4 as BeautifulSoup


def getDOMImplementation(dom = None, **kwds):
    from .DOMImplementation import DOMImplementation
    return DOMImplementation(dom if dom else BeautifulSoup.BeautifulSoup(), **kwds)


def parseString(html, **kwds):
    from .DOMImplementation import DOMImplementation
    return DOMImplementation(BeautifulSoup.BeautifulSoup(html, "html.parser"), **kwds)


def parse(_file, **kwds):
    if isinstance(_file, six.string_types):
        with open(_file, 'r') as f:
            return parseString(f.read())

    return parseString(_file.read(), **kwds)
