#!/usr/bin/env python

import sys
import re
import string
import logging

log = logging.getLogger("Thug")

from urlparse import urlparse

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import bs4 as BeautifulSoup
import PyV8

from Document import Document
from .HTMLCollection import HTMLCollection
from .HTMLElement import HTMLElement
from .text_property import text_property
from .xpath_property import xpath_property

class HTMLDocument(Document):
    title       = xpath_property("/html/head/title/text()")
    body        = xpath_property("/html/body[1]")
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
        self.current        = None

    def __getattr__(self, name):
        if name in self.__dict__:
            return self.__dict__[name]
        
        # Internet Explorer is not compliant with ECMAScript 5 spec 8.6.2
        if log.ThugOpts.Personality.isIE(): 
            raise TypeError()

        return None

    def getWindow(self):
        return self._win

    def setWindow(self, win):
        self._win = win

    window = property(getWindow, setWindow)

    @property
    def referrer(self):
        return str(self._referer)

    @property
    def lastModified(self):
        return self._lastModified

    def getCookie(self):
        return self._cookie

    def setCookie(self, value):
        self._cookie = value

    cookie = property(getCookie, setCookie)
        
    @property
    def domain(self):
        return urlparse(self._win.url).hostname if self._win else ''
        
    @property
    def URL(self):
        return self._win.url if self._win else ''

    @property
    def documentElement(self):
        return HTMLElement(self, self.doc.find('html'))

    # FIXME
    @property
    def querySelectorAll(self):
        return None

    # FIXME
    @property
    def readyState(self):
        return "complete"

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
        else:
            tag    = self.current
            parent = tag.parent
            pos    = parent.contents.index(tag) + 1

            soup   = BeautifulSoup.BeautifulSoup(html, "html5lib")
            #for tag in BeautifulSoup.BeautifulSoup(html, "html5lib").contents:
            for tag in soup.body.children:
                parent.insert(pos, tag)

                pos += 1

                name = getattr(tag, "name", None)
                if name is None:
                    continue

                handler = getattr(self._win.doc.DFT, "handle_%s" % (name, ), None)
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
