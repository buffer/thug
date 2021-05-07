#!/usr/bin/env python

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
