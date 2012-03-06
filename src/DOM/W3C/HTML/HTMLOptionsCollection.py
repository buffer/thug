#!/usr/bin/env python
from __future__ import with_statement

import sys, re, string

import bs4 as BeautifulSoup
import PyV8

from DOMException import DOMException
from HTMLCollection import HTMLCollection

# Introduced in DOM Level 2
class HTMLOptionsCollection(HTMLCollection):
    def __init__(self, doc, nodes):
        HTMLCollection.__init__(self, doc, nodes)

    def getLength(self):
        return len(self.nodes)

    def setLength(self):
        raise DOMException(DOMException.NOT_SUPPORTED_ERR)

    length = property(getLength, setLength)

