#!/usr/bin/env python

import logging
import bs4

from .Node import Node
from thug.DOM.W3C.Events.DocumentEvent import DocumentEvent
from thug.DOM.W3C.Views.DocumentView import DocumentView

log = logging.getLogger("Thug")


class Document(Node, DocumentEvent, DocumentView):
    def __init__(self, doc):
        Node.__init__(self, doc)
        DocumentEvent.__init__(self, doc)
        DocumentView.__init__(self, doc)
        self.__init_document_personality()

    def __init_document_personality(self):
        self.__init_characterSet()

        if log.ThugOpts.Personality.isIE():
            self.__init_document_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_document_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_document_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_document_personality_Safari()
            return

    def __init_characterSet(self):
        self._character_set = ""
        for meta in self.doc.find_all("meta"):
            if 'charset' in meta.attrs:
                self._characterSet = meta.attrs['charset'].upper()

    def __init_document_personality_IE(self):
        self.defaultCharset = self._defaultCharset

        if log.ThugOpts.Personality.browserMajorVersion > 7:
            self.querySelectorAll = self._querySelectorAll
            self.querySelector    = self._querySelector

        if log.ThugOpts.Personality.browserMajorVersion > 8:
            self.getElementsByClassName = self._getElementsByClassName
            self.characterSet           = self._characterSet
            self.inputEncoding          = self._inputEncoding
        else:
            self.charset                = self._characterSet

        if log.ThugOpts.Personality.browserMajorVersion > 10:
            self.__proto__ = None

    def __init_document_personality_Firefox(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.getElementsByClassName = self._getElementsByClassName
        self.characterSet           = self._characterSet
        self.inputEncoding          = self._inputEncoding

    def __init_document_personality_Chrome(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.getElementsByClassName = self._getElementsByClassName
        self.characterSet           = self._characterSet
        self.inputEncoding          = self._inputEncoding

    def __init_document_personality_Safari(self):
        self.querySelectorAll       = self._querySelectorAll
        self.querySelector          = self._querySelector
        self.getElementsByClassName = self._getElementsByClassName
        self.characterSet           = self._characterSet
        self.inputEncoding          = self._inputEncoding

    def _querySelectorAll(self, selectors):
        from .NodeList import NodeList

        try:
            s = self.doc.select(selectors)
        except Exception: # pragma: no cover
            return NodeList(self.doc, [])

        return NodeList(self.doc, s)

    def _querySelector(self, selectors):
        from .DOMImplementation import DOMImplementation

        try:
            s = self.doc.select(selectors)
        except Exception: # pragma: no cover
            return None

        return DOMImplementation.createHTMLElement(self, s[0]) if s and s[0] else None

    # Introduced in DOM Level 3
    @property
    def textContent(self):
        return None

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
        from .NodeList import NodeList
        return NodeList(self.doc, self.doc.contents)

    @property
    def doctype(self):
        from .DocumentType import DocumentType

        _doctype = getattr(self, '_doctype', None)
        if _doctype:
            return _doctype

        tags = [t for t in self.doc if isinstance(t, bs4.Doctype)]
        if not tags:
            return None

        self._doctype = DocumentType(self.doc, tags[0])
        return self._doctype

    @property
    def implementation(self):
        return self

    @property
    def documentElement(self): # pragma: no cover
        from thug.DOM.W3C.HTML.HTMLHtmlElement import HTMLHtmlElement

        html = self.doc.find('html')
        return HTMLHtmlElement(self, html if html else self.doc)

    def getCharacterSet(self):
        return self._character_set

    def setCharacterSet(self, value):
        self._character_set = value

    _characterSet = property(getCharacterSet, setCharacterSet)

    @property
    def _inputEncoding(self):
        for meta in self.doc.find_all("meta"):
            if 'charset' in meta.attrs:
                return meta.attrs['charset'].upper()

        return ""

    @property
    def _defaultCharset(self):
        return "Windows-1252"

    def createElement(self, tagname, tagvalue = None):
        from .DOMImplementation import DOMImplementation

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_createelement_count()

        # Internet Explorer 8 and below also support the syntax
        # document.createElement('<P>')
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
            if tagname.startswith('<') and '>' in tagname:
                tagname = tagname[1:].split('>')[0]

        return DOMImplementation.createHTMLElement(self, bs4.Tag(parser = self.doc, name = tagname))

    def createDocumentFragment(self):
        from .DocumentFragment import DocumentFragment

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.increase_createdocumentfragment_count()

        return DocumentFragment(self)

    def createTextNode(self, data):
        from .Text import Text
        return Text(self, bs4.NavigableString(data))

    def createComment(self, data):
        from .Comment import Comment
        return Comment(self, bs4.Comment(data))

    def createCDATASection(self, data):
        from .CDATASection import CDATASection
        return CDATASection(self, bs4.CData(data))

    def createProcessingInstruction(self, target, data):
        from .ProcessingInstruction import ProcessingInstruction
        return ProcessingInstruction(self, target, bs4.ProcessingInstruction(data))

    def createAttribute(self, name):
        from .Attr import Attr
        return Attr(self, None, name)

    def createEntityReference(self, name):
        from .EntityReference import EntityReference
        return EntityReference(self, name)

    def getElementsByTagName(self, tagname):
        from .NodeList import NodeList

        if tagname in ('*', ):
            s = [p for p in self.doc.find_all(text = False)]
            return NodeList(self.doc, s)

        return NodeList(self.doc, self.doc.find_all(tagname.lower()))

    def _getElementsByClassName(self, classname):
        from .NodeList import NodeList
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
