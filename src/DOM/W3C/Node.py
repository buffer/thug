#!/usr/bin/env python
from __future__ import with_statement

import sys
from HTML import BeautifulSoup
import PyV8

from abstractmethod import abstractmethod
from DOMException import DOMException
from Events.EventTarget import EventTarget


class Node(PyV8.JSClass, EventTarget):
    # NodeType
    ELEMENT_NODE                   = 1
    ATTRIBUTE_NODE                 = 2
    TEXT_NODE                      = 3
    CDATA_SECTION_NODE             = 4
    ENTITY_REFERENCE_NODE          = 5
    ENTITY_NODE                    = 6
    PROCESSING_INSTRUCTION_NODE    = 7
    COMMENT_NODE                   = 8
    DOCUMENT_NODE                  = 9
    DOCUMENT_TYPE_NODE             = 10
    DOCUMENT_FRAGMENT_NODE         = 11
    NOTATION_NODE                  = 12
    
    def __init__(self, doc):
        self.doc = doc

    def __repr__(self):
        return "<Node %s at 0x%08X>" % (self.nodeName, id(self))
                
    def __eq__(self, other):
        return hasattr(other, "doc") and self.doc == other.doc
        
    def __ne__(self, other):
        return not self.__eq__(other)
    
    @property
    @abstractmethod
    def nodeType(self):
        pass
    
    @property
    @abstractmethod
    def nodeName(self):
        pass
    
    @abstractmethod
    def getNodeValue(self):
        return None
    
    @abstractmethod
    def setNodeValue(self, value):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)
    
    nodeValue = property(getNodeValue, setNodeValue)
    
    @property
    def attributes(self):
        return None
    
    @property
    def childNodes(self):
        return NodeList(self.doc, [])
        
    @property
    def firstChild(self):
        return None
            
    @property
    def lastChild(self):
        return None
            
    @property
    def nextSibling(self):
        return None
            
    @property
    def previousSibling(self):
        return None
            
    @property
    def parentNode(self):
        return None

    # Introduced in DOM Level 2
    @property
    def namespaceURI(self):
        return None

    # Introduced in DOM Level 2
    @property
    def prefix(self):
        return None

    # Introduced in DOM Level 2
    @property 
    def localName(self):
        return None
   
    # Modified in DOM Level 2
    @property
    def ownerDocument(self):
        return self.doc
    
    def insertBefore(self, newChild, refChild):
        raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

    def insertAfter(self, newChild, refChild):
        raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

    def replaceChild(self, newChild, oldChild):
        raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)
    
    def removeChild(self, oldChild):
        raise DOMException(DOMException.NOT_FOUND_ERR)
    
    def appendChild(self, newChild):
        raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)
    
    def hasChildNodes(self):
        return False

    # Modified in DOM Level 2
    def normalize(self):
        pass

    # Introduced in DOM Level 2
    def isSupported(self, feature, version):
        from DOMImplementation import DOMImplementation
        return DOMImplementation.hasFeature(feature, version)

    # Introduced in DOM Level 2
    def hasAttributes(self):
        return False
    
    @abstractmethod
    def cloneNode(self, deep):
        pass
    
    @staticmethod
    def wrap(doc, obj):
        from Element import Element

        if obj is None:
            return None
        
        if type(obj) == BeautifulSoup.CData:
            from CDATASection import CDATASection

            return CDATASection(doc, obj)
        
        if type(obj) == BeautifulSoup.NavigableString:
            from Text import Text

            return Text(doc, obj)        
       
        return Element(doc, obj)

