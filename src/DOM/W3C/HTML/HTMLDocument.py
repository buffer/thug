#!/usr/bin/env python

import sys
import re
import string
import logging

log = logging.getLogger("Thug")

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    from io import StringIO
except ImportError:
    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO

import bs4 as BeautifulSoup
import PyV8

from Document import Document
from DOMException import DOMException
from .HTMLCollection import HTMLCollection
from .HTMLElement import HTMLElement
from .HTMLBodyElement import HTMLBodyElement
from .text_property import text_property
from .xpath_property import xpath_property


class HTMLDocument(Document):
    title       = xpath_property("/html/head/title/text()")
    #body        = xpath_property("/html/body[1]", readonly = True)
    images      = xpath_property("//img", readonly = True)
    applets     = xpath_property("//applet", readonly = True)
    forms       = xpath_property("//form", readonly = True)
    links       = xpath_property("//a[@href]", readonly = True)
    anchors     = xpath_property("//a[@name]", readonly = True)
    innerHTML   = text_property()

    def __init__(self, doc, win = None, referer = None, lastModified = None, cookie = ''):
        Document.__init__(self, doc)

        self._win           = win
        self._referer       = referer
        self._lastModified  = lastModified
        self._cookie        = cookie
        self._html          = None
        self._domain        = urlparse(self._win.url).hostname if self._win else ''
        self.current        = None

    def __getattr__(self, attr):
        if self._win and getattr(self._win, "doc", None):
            if attr in self._win.doc.DFT.handled_on_events:
                return None

        #print("[HTMLDocument __getattr__] %s" % (attr, ))
        return self.getElementById(attr)

    def getWindow(self):
        return self._win

    def setWindow(self, win):
        self._win = win

    window = property(getWindow, setWindow)

    @property
    def body(self):
        tag = self.doc.find('body')
        return HTMLBodyElement(self.doc, tag if tag else self.doc)

    @property
    def tag(self):
        return self

    @property
    def _node(self):
        return self

    @property
    def referrer(self):
        if self._referer:
            return str(self._referer)

        return ""

    @property
    def lastModified(self):
        return self._lastModified

    def getCookie(self):
        return self._cookie

    def setCookie(self, value):
        self._cookie = value

    cookie = property(getCookie, setCookie)
        
    def getDomain(self):
        return self._domain
    
    def setDomain(self, value):
        self._domain = value

    domain = property(getDomain, setDomain)

    @property
    def URL(self):
        return self._win.url if self._win else ''

    @property
    def documentElement(self):
        return HTMLElement(self, self.doc.find('html'))

    def _querySelectorAll(self):
        pass

    # FIXME
    @property
    def readyState(self):
        return "complete"

    @property
    def compatMode(self):
        return "BackCompat"

    def open(self, mimetype = 'text/html', replace = False):
        self._html = StringIO()

        return self
    
    def close(self):
        html = self._html.getvalue()
        self._html.close()
        self._html = None

        self.doc = BeautifulSoup.BeautifulSoup(html, "html5lib")

    def write(self, html):
        if self._html:
            self._html.write(html)
            return

        tag    = self.current
        parent = tag.parent
        pos    = parent.contents.index(tag) + 1

        soup = BeautifulSoup.BeautifulSoup(html, "html5lib")
        soup.html.unwrap()
        soup.head.unwrap()
        soup.body.unwrap()

        for tag in soup:
            parent.insert(pos, tag)

            pos += 1

            name = getattr(tag, "name", None)
            if name in ('script', None):
                continue

            try:
                handler = getattr(self._win.doc.DFT, "handle_%s" % (name, ), None)
            except:
                handler = getattr(log.DFT, "handle_%s" % (name, ), None)

            if handler:
                handler(tag)

    def writeln(self, text):
        self.write(text + "\n")
   
    # DOM Level 2 moves getElementbyId in Document object inherited by 
    # HTMLDocument
    #
    #def getElementById(self, elementId):
    #    tag = self.doc.find(id = elementId)
    #    return DOMImplementation.createHTMLElement(self.doc, tag) if tag else None

    def getElementsByName(self, elementName):
        tags = self.doc.find_all(attrs = {'name': elementName})
        
        return HTMLCollection(self.doc, tags)
