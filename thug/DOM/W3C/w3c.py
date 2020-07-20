#!/usr/bin/env python

# import six

import logging
import bs4

log = logging.getLogger("Thug")


def getDOMImplementation(dom = None, **kwds):
    from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

    return DOMImplementation(dom if dom else bs4.BeautifulSoup('', 'lxml'), **kwds)


def parseString(html, **kwds):
    from thug.DOM.W3C.Core.DOMImplementation import DOMImplementation

    soup = log.HTMLInspector.run(html, "html.parser")
    return DOMImplementation(soup, **kwds)


# def parse(_file, **kwds):
#    if isinstance(_file, six.string_types):
#        with open(_file, 'r') as f:
#            return parseString(f.read())
#
#    return parseString(_file.read(), **kwds)
