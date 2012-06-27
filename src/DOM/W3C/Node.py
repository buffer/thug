#!/usr/bin/env python

import sys
import bs4 as BeautifulSoup
import PyV8
import logging

from abstractmethod import abstractmethod
from DOMException import DOMException
from Events.EventTarget import EventTarget
from NodeList import NodeList

log = logging.getLogger("Thug")


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
        EventTarget.__init__(self)

        # Internet Explorer < 9 does not implement compareDocumentPosition
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserVersion < '9.0':
            return

        self.compareDocumentPosition = self._compareDocumentPosition

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

    def findChild(self, child):
        try:
            return self.tag.contents.index(child.tag)
        except:
            return -1

    def is_readonly(self, node):
        return node.nodeType in (Node.DOCUMENT_TYPE_NODE,
                                 Node.NOTATION_NODE,
                                 Node.ENTITY_REFERENCE_NODE,
                                 Node.ENTITY_NODE, )

    def is_text(self, node):
        return node.nodeType in (Node.TEXT_NODE,
                                 Node.PROCESSING_INSTRUCTION_NODE,
                                 Node.CDATA_SECTION_NODE,
                                 Node.COMMENT_NODE, )
    
    def insertBefore(self, newChild, refChild):
        if not newChild:
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)
        
        if not isinstance(newChild, Node):
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

        # If refChild is null, insert newChild at the end of the list 
        # of children
        if not refChild:
            return self.appendChild(newChild)

        if not isinstance(refChild, Node):
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

        index = self.findChild(refChild)
        if index < 0 and not self.is_text(refChild):
            raise DOMException(DOMException.NOT_FOUND_ERR)

        # If the newChild is already in the tree, it is first removed
        if getattr(newChild, 'tag', None) and newChild.tag in self.tag.contents:
            self.tag.contents.remove(newChild.tag)

        if self.is_text(newChild):
            self.tag.insert(index, newChild.data.output_ready())
            return newChild

        if newChild.nodeType in (Node.DOCUMENT_FRAGMENT_NODE, ):
            # self.tag.insert(index, newChild.tag.findChild())
            node = None

            for p in newChild.tag.find_all_next():
                if node is None:
                    self.tag.insert(index, p)
                else:
                    node.append(p)

                node = p
                    
            return newChild

        self.tag.insert(index, newChild.tag)
        return newChild

    def replaceChild(self, newChild, oldChild):
        # NO_MODIFICATION_ALLOWED_ERR: Raised if this node or the parent of 
        # the new node is readonly.
        if self.is_readonly(self):
            raise DOMException(DOMException.NO_MODIFICATION_ALLOWED)

        parent = getattr(newChild, 'parentNode', None)
        if parent:
            if self.is_readonly(parent):
                raise DOMException(DOMException.NO_MODIFICATION_ALLOWED)

        if not newChild or not oldChild:
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

        if not isinstance(newChild, Node) or not isinstance(oldChild, Node):
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

        index = self.findChild(oldChild)
        if index < 0 and not self.is_text(refChild):
            raise DOMException(DOMException.NOT_FOUND_ERR)

        if self.is_text(newChild):
            self.tag.contents[index] = newChild.data.output_ready()
            return oldChild

        if newChild.nodeType in (Node.DOCUMENT_FRAGMENT_NODE, ):
            #self.tag.contents[index] = newChild.tag.findChild()
            node = None

            for p in newChild.tag.find_all_next():
                if node is None:
                    self.tag.contents[index] = p
                else:
                    node.append(p)

                node = p

            return oldChild

        self.tag.contents[index] = newChild.tag
        return oldChild

    def removeChild(self, oldChild):
        # NO_MODIFICATION_ALLOWED_ERR: Raised if this node is readonly
        if self.is_readonly(self):
            raise DOMException(DOMException.NO_MODIFICATION_ALLOWED)

        if not oldChild:
            raise DOMException(DOMException.NOT_FOUND_ERR)

        if not isinstance(oldChild, Node):
            raise DOMException(DOMException.NOT_FOUND_ERR)

        index = self.findChild(oldChild)
        if index < 0 and not self.is_text(oldChild):
            raise DOMException(DOMException.NOT_FOUND_ERR)

        if getattr(oldChild, 'tag', None) and oldChild.tag in self.tag.contents:
            self.tag.contents.remove(oldChild.tag)

        return oldChild

    def appendChild(self, newChild):
        # NO_MODIFICATION_ALLOWED_ERR: Raised if this node is readonly
        if self.is_readonly(self):
            raise DOMException(DOMException.NO_MODIFICATION_ALLOWED)

        if self.is_text(self):
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

        if not newChild:
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

        if not isinstance(newChild, Node):
            raise DOMException(DOMException.HIERARCHY_REQUEST_ERR)

        # If the newChild is already in the tree, it is first removed
        if getattr(newChild, 'tag', None) and newChild.tag in self.tag.contents:
            self.tag.contents.remove(newChild.tag)

        if self.is_text(newChild):
            self.tag.append(newChild.data.output_ready())
            return newChild

        if newChild.nodeType in (Node.DOCUMENT_FRAGMENT_NODE, ):
            #self.tag.append(newChild.tag.findChild())
            node = self.tag
            for p in newChild.tag.find_all_next():
                node.append(p)
                node = p

            return newChild

        self.tag.append(newChild.tag)
        return newChild

    def hasChildNodes(self):
        return len(self.tag.contents) > 0

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
   
    # Introduced in DOM Level 3
    def _compareDocumentPosition(self, node):
       return None

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

