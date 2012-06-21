#!/usr/bin/env python

import sys
import re
import string
import logging

log = logging.getLogger("Thug")

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import bs4 as BeautifulSoup
import PyV8

from DOMException import DOMException
from Node import Node
from NodeList import NodeList
from DocumentFragment import DocumentFragment
from DocumentType import DocumentType
from Element import Element
from Comment import Comment
from CDATASection import CDATASection
from Attr import Attr
from EntityReference import EntityReference
from ProcessingInstruction import ProcessingInstruction
from Events.DocumentEvent import DocumentEvent
from Views.DocumentView import DocumentView

class Document(Node, DocumentEvent, DocumentView):
    def __str__(self):
        return str(self.doc)

    def __unicode__(self):
        return unicode(self.doc)

    def __repr__(self):
        return "<Document at 0x%08X>" % id(self)

    @property
    def nodeType(self):
        return Node.DOCUMENT_NODE
    
    @property
    def nodeName(self):
        return "#document"
    
    @property
    def nodeValue(self):
        return None
    
    @property
    def childNodes(self):
        return NodeList(self.doc, self.doc.contents)
        
    @property
    def doctype(self):
        for tag in self.doc:
            if isinstance(tag, BeautifulSoup.Declaration) and tag.startswith("DOCTYPE"):
                return DocumentType(self.doc, tag)
                
        return None
    
    @property
    def implementation(self):
        return self
    
    @property
    def documentElement(self):        
        return Element(self, self.doc.find('html'))
        
    onCreateElement = None
    
    def createElement(self, tagname):
        from DOMImplementation import DOMImplementation

        # Internet Explorer 8 and below also support the syntax
        # document.createElement('<P>')
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserVersion < '9.0':
            if tagname.startswith('<') and '>' in tagname:
                tagname = tagname[1:].split('>')[0]

        element = DOMImplementation.createHTMLElement(self, BeautifulSoup.Tag(parser = self.doc, name = tagname))
        if self.onCreateElement:
            self.onCreateElement(element)
        
        return element
    
    def createDocumentFragment(self):
        return DocumentFragment(self)
    
    def createTextNode(self, data):
        from Text import Text
        return Text(self, BeautifulSoup.NavigableString(data))
    
    def createComment(self, data):
        return Comment(self, data)
    
    def createCDATASection(self, data):
        return CDATASection(self, data)
    
    def createProcessingInstruction(self, target, data):
        return ProcessingInstruction(self, target, data)
    
    def createAttribute(self, name):
        return Attr(self, None, name)
    
    def createEntityReference(self, name):
        return EntityReference(self, name)
    
    def getElementsByTagName(self, tagname):
        if log.ThugOpts.Personality.isIE() and tagname in ('*', ):
            s = [p for p in self.doc.find_all(text = False)]
            return NodeList(self.doc, s)

        return NodeList(self.doc, self.doc.find_all(tagname.lower()))
    
    @property
    def all(self):
        return self.getElementsByTagName('*')

    # Introduced in DOM Level 2
    def getElementById(self, elementId):
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserVersion < '8.0':
            return self._getElementById_IE67(elementId)

        return self._getElementById(elementId)

    def _getElementById(self, elementId):
        from DOMImplementation import DOMImplementation

        tag = self.doc.find(id = elementId)
        return DOMImplementation.createHTMLElement(self, tag) if tag else None

    # Internet Explorer 6 and 7 getElementById is broken and returns 
    # elements with 'id' or 'name' attributes equal to elementId
    def _getElementById_IE67(self, elementId):
        from DOMImplementation import DOMImplementation

        def _match_tag(tag, p):
            return p in tag.attrs and tag.attrs[p] == elementId

        def match_tag(tag):
            if _match_tag(tag, 'id') or _match_tag(tag, 'name'):
                return True

            return False

        def filter_tags_id_name(tag):
            return tag.has_key('id') or tag.has_key('name')

        for tag in self.doc.find_all(filter_tags_id_name):
            if match_tag(tag):
                return DOMImplementation.createHTMLElement(self, tag)

        return None

    # Introduced in DOM Level 2
    def importNode(self, importedNode, deep):
        # TODO
        pass

    # Modified in DOM Level 2
    @property
    def ownerDocument(self):
        return None

