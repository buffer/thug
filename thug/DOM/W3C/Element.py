#!/usr/bin/env python

import six

import logging

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from .Attr import Attr
from .Node import Node
from .NodeList import NodeList
from .NamedNodeMap import NamedNodeMap

from .Style.CSS.ElementCSSInlineStyle import ElementCSSInlineStyle
log = logging.getLogger("Thug")

class Element(Node, ElementCSSInlineStyle):
    def __init__(self, doc, tag):
        self.tag       = tag
        self.tag._node = self
        Node.__init__(self, doc)
        self.__init_personality()

    def __init_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_personality_Safari()
            return

        if log.ThugOpts.Personality.isOpera():
            self.__init_personality_Opera()

    def __init_personality_IE(self):
        if log.ThugOpts.Personality.browserMajorVersion > 7:
            self.querySelectorAll = self._querySelectorAll
            self.querySelector    = self._querySelector

        if log.ThugOpts.Personality.browserMajorVersion > 8:
            self.getElementsByClassName = self._getElementsByClassName

    def __init_personality_Firefox(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.getElementsByClassName = self._getElementsByClassName

    def __init_personality_Chrome(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.getElementsByClassName = self._getElementsByClassName

    def __init_personality_Safari(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.getElementsByClassName = self._getElementsByClassName

    def __init_personality_Opera(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.getElementsByClassName = self._getElementsByClassName

    def _querySelectorAll(self, selectors):
        try:
            s = self.tag.select(selectors)
        except: #pylint:disable=bare-except
            return NodeList(self.doc, [])

        return NodeList(self.doc, s)

    def _querySelector(self, selectors):
        from .DOMImplementation import DOMImplementation

        try:
            s = self.tag.select(selectors)
        except: #pylint:disable=bare-except
            return None

        if s and s[0]:
            return DOMImplementation.createHTMLElement(self, s[0])

        return None

    def __str__(self):
        return str(self.tag)

    def __unicode__(self):
        return unicode(self.tag)
        
    def __repr__(self):
        return "<Element %s at 0x%08X>" % (self.tag.name, id(self))
        
    def __eq__(self, other):
        return Node.__eq__(self, other) and hasattr(other, "tag") and self.tag == other.tag

    @property
    def nodeType(self):
        return Node.ELEMENT_NODE
       
    @property
    def nodeName(self):
        return self.tagName
    
    @property
    def nodeValue(self):
        return None
    
    @property
    def attributes(self):
        return NamedNodeMap(self)    
    
    @property
    def parentNode(self):
        return Node.wrap(self.doc, self.tag.parent) if self.tag.parent else None
    
    @property
    def childNodes(self):
        #return Node.wrap(self.doc, NodeList(self.doc, self.tag.contents))
        return NodeList(self.doc, self.tag.contents)
        
    @property
    def firstChild(self):
        return Node.wrap(self.doc, self.tag.contents[0]) if len(self.tag) > 0 else None
            
    @property
    def lastChild(self):
        return Node.wrap(self.doc, self.tag.contents[-1]) if len(self.tag) > 0 else None
            
    @property
    def nextSibling(self):
        return Node.wrap(self.doc, self.tag.next_sibling)
            
    @property
    def previousSibling(self):
        return Node.wrap(self.doc, self.tag.previous_sibling)
  
    # Introduced in DOM Level 2
    def hasAttributes(self):
        return self.attributes.length > 0

    # Introduced in DOM Level 2
    def hasAttribute(self, name):
        return self.tag.has_attr(name)
        
    @property
    def tagName(self):
        return self.tag.name.upper()
    
    def getAttribute(self, name, flags = 0):
        if not isinstance(name, six.string_types):
            name = str(name)

        if log.ThugOpts.Personality.isIE():
            if log.ThugOpts.Personality.browserMajorVersion < 8:
                # flags parameter is only supported in Internet Explorer earlier 
                # than version 8.
                #
                # A value of 0 means that the search is case-insensitive and the 
                # returned value does not need to be converted. Other values can 
                # be any combination of the following integer constants with the 
                # bitwise OR operator:
                # 
                # 1   Case-sensitive search
                # 2   Returns the value as a string
                # 4   Returns the value as an URL

                if not flags & 1:
                    name = name.lower()

            value = self.tag[name] if self.tag.has_attr(name) else None

            # FIXME (flags 2 and 4 not implemented yet)
            return value

        return self.tag[name] if self.tag.has_attr(name) else ""

    def setAttribute(self, name, value):
        if not isinstance(name, six.string_types):
            name = str(name)

        self.tag[name] = value

        if name.lower() in ('src', 'archive'):
            s = urlparse.urlsplit(value)

            handler = getattr(log.SchemeHandler, 'handle_%s' % (s.scheme, ), None)
            if handler:
                handler(self.doc.window, value)
                return
            
            try:
                response = self.doc.window._navigator.fetch(value, redirect_type = "element workaround")
            except: #pylint:disable=bare-except
                return

            if response is None:
                return

            if response.status_code == 404:
                return

            ctype = response.headers.get('content-type', None)
            if ctype is None:
                return

            handler = log.MIMEHandler.get_handler(ctype)
            if handler:
                handler(self.doc.window.url, response.content)

    def removeAttribute(self, name):
        del self.tag[name]
        
    def getAttributeNode(self, name):
        return Attr(self.doc, self, name) if self.tag.has_attr(name) else None
    
    def setAttributeNode(self, attr):
        self.tag[attr.name] = attr.value
    
    def removeAttributeNode(self, attr):
        del self.tag[attr.name]
    
    def getElementsByTagName(self, tagname):
        return NodeList(self.doc, self.tag.find_all(tagname))
        #return self.doc.getElementsByTagName(tagname)

    def _getElementsByClassName(self, classname):
        return NodeList(self.doc, self.tag.find_all(class_ = classname))
