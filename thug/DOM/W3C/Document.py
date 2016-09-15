#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")

import bs4 as BeautifulSoup

from .Node import Node
from .NodeList import NodeList
from .DocumentFragment import DocumentFragment
from .DocumentType import DocumentType
from .Element import Element
from .Comment import Comment
from .Text import Text
from .CDATASection import CDATASection
from .Attr import Attr
from .EntityReference import EntityReference
from .ProcessingInstruction import ProcessingInstruction
from .Events.DocumentEvent import DocumentEvent
from .Views.DocumentView import DocumentView

class Document(Node, DocumentEvent, DocumentView):
    def __init__(self, doc):
        Node.__init__(self, doc)
        DocumentEvent.__init__(self, doc)
        DocumentView.__init__(self, doc)
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
            s = self.doc.select(selectors)
        except: #pylint:disable=bare-except
            return NodeList(self.doc, [])

        return NodeList(self.doc, s)

    def _querySelector(self, selectors):
        from .DOMImplementation import DOMImplementation

        try:
            s = self.doc.select(selectors)
        except: #pylint:disable=bare-except
            return None

        if s and s[0]:
            return DOMImplementation.createHTMLElement(self, s[0])

        return None

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
    
    def createElement(self, tagname, tagvalue = None):
        from .DOMImplementation import DOMImplementation

        # Internet Explorer 8 and below also support the syntax
        # document.createElement('<P>')
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
            if tagname.startswith('<') and '>' in tagname:
                tagname = tagname[1:].split('>')[0]

        element = DOMImplementation.createHTMLElement(self, BeautifulSoup.Tag(parser = self.doc, name = tagname))
        if self.onCreateElement:
            self.onCreateElement(element) #pylint:disable=not-callable
        
        return element
    
    def createDocumentFragment(self):
        return DocumentFragment(self)
    
    def createTextNode(self, data):
        return Text(self, BeautifulSoup.NavigableString(data))
    
    def createComment(self, data):
        return Comment(self, BeautifulSoup.Comment(data))
    
    def createCDATASection(self, data):
        return CDATASection(self, BeautifulSoup.CData(data))
    
    def createProcessingInstruction(self, target, data):
        return ProcessingInstruction(self, target, BeautifulSoup.ProcessingInstruction(data))
    
    def createAttribute(self, name):
        return Attr(self, None, name)
    
    def createEntityReference(self, name):
        return EntityReference(self, name)
    
    def getElementsByTagName(self, tagname):
        if log.ThugOpts.Personality.isIE() and tagname in ('*', ):
            s = [p for p in self.doc.find_all(text = False)]
            return NodeList(self.doc, s)

        return NodeList(self.doc, self.doc.find_all(tagname.lower()))

    def _getElementsByClassName(self, classname):
        return NodeList(self.doc, self.doc.find_all(class_ = classname))

    # Introduced in DOM Level 2
    def getElementById(self, elementId):
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 8:
            return self._getElementById_IE67(elementId)

        return self._getElementById(elementId)

    def _getElementById(self, elementId):
        from .DOMImplementation import DOMImplementation

        tag = self.doc.find(id = elementId)
        return DOMImplementation.createHTMLElement(self, tag) if tag else None

    # Internet Explorer 6 and 7 getElementById is broken and returns 
    # elements with 'id' or 'name' attributes equal to elementId
    def _getElementById_IE67(self, elementId):
        from .DOMImplementation import DOMImplementation

        def _match_tag(tag, p):
            return p in tag.attrs and tag.attrs[p] == elementId

        def match_tag(tag, _id):
            if _match_tag(tag, _id):
                return True

            return False

        def filter_tags_id(tag):
            return tag.has_attr('id')

        def filter_tags_name(tag):
            return tag.has_attr('name')

        for tag in self.doc.find_all(filter_tags_id):
            if match_tag(tag, 'id'):
                return DOMImplementation.createHTMLElement(self, tag)

        for tag in self.doc.find_all(filter_tags_name):
            if match_tag(tag, 'name'):
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

    def execCommand(self, commandIdentifier, userInterface = False, value = None):
        pass
