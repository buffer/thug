#!/usr/bin/env python

import logging
import bs4

log = logging.getLogger("Thug")


def getDOMImplementation(dom=None, **kwds):
    return log.DOMImplementation(dom if dom else bs4.BeautifulSoup("", "lxml"), **kwds)


def parseString(html, **kwds):
    soup = log.HTMLInspector.run(html, "html.parser")
    return log.DOMImplementation(soup, **kwds)
