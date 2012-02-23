#!/usr/bin/env python
from __future__ import with_statement

import sys, re, string

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from HTML import BeautifulSoup
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


class Document(Node, DocumentEvent):
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

        element = DOMImplementation.createHTMLElement(self, BeautifulSoup.Tag(self.doc, tagname))
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
        return Attr(None, name)
    
    def createEntityReference(self, name):
        return EntityReference(self, name)
    
    def getElementsByTagName(self, tagname):
        if self.window._personality.startswith(('xpie', 'w2kie')) and tagname in ('*', ):
            s = [p for p in self.doc.findAll(text = False)]
            return NodeList(self.doc, s)

        return NodeList(self.doc, self.doc.findAll(tagname.lower()))

    # Introduced in DOM Level 2
    def getElementById(self, elementId):
        from DOMImplementation import DOMImplementation

        tag = self.doc.find(id = elementId)
        return DOMImplementation.createHTMLElement(self, tag) if tag else None

    # Introduced in DOM Level 2
    def importNode(self, importedNode, deep):
        # TODO
        pass

    # Modified in DOM Level 2
    @property
    def ownerDocument(self):
        return None

