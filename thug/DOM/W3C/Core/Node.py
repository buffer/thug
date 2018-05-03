#!/usr/bin/env python

import copy
import logging
import bs4 as BeautifulSoup

from thug.DOM.JSClass import JSClass
from .abstractmethod import abstractmethod
from .DOMException import DOMException

from thug.DOM.W3C.Events.EventTarget import EventTarget

log = logging.getLogger("Thug")


class Node(JSClass, EventTarget):
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
        self.__init_personality()

    def __repr__(self):
        return "<Node %s at 0x%08X>" % (self.nodeName, id(self))

    def __eq__(self, other):
        return hasattr(other, "doc") and self.doc == other.doc

    def __ne__(self, other):
        return not self.__eq__(other)

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
        self.applyElement = self._applyElement

        # Internet Explorer < 9 does not implement compareDocumentPosition
        if log.ThugOpts.Personality.browserMajorVersion >= 9:
            self.compareDocumentPosition = self._compareDocumentPosition

    def __init_personality_Firefox(self):
        self.compareDocumentPosition = self._compareDocumentPosition

    def __init_personality_Chrome(self):
        self.compareDocumentPosition = self._compareDocumentPosition

    def __init_personality_Safari(self):
        self.compareDocumentPosition = self._compareDocumentPosition

    def __init_personality_Opera(self):
        self.compareDocumentPosition = self._compareDocumentPosition

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

    def getTextContent(self):
        return self.tag.string

    def setTextContent(self, value):
        self.tag.string = value

    # Introduced in DOM Level 3
    textContent = property(getTextContent, setTextContent)

    @property
    def attributes(self):
        from .NamedNodeMap import NamedNodeMap
        return NamedNodeMap(self)

    @property
    def childNodes(self):
        from .NodeList import NodeList
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

    @property
    def parentNode(self):
        return Node.wrap(self.doc, self.tag.parent) if self.tag.parent else None

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
        return log.DFT.window.doc
        # return self.doc

    def findChild(self, child):
        # try:
        #    return self.tag.contents.index(child.tag)
        # except:
        #    return -1
        if getattr(child, 'tag', None) and child.tag in self.tag.contents:
            childHash = hash(child.tag._node)

            for p in self.tag.contents:
                if getattr(p, '_node', None) is None:
                    continue

                if childHash == hash(p._node):
                    return self.tag.contents.index(p)

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

        # index = self.findChild(refChild)
        # if index < 0 and not self.is_text(refChild):
        #    raise DOMException(DOMException.NOT_FOUND_ERR)

        # If the newChild is already in the tree, it is first removed
        if getattr(newChild, 'tag', None) and newChild.tag in self.tag.contents:
            newChildHash = hash(newChild.tag._node)

            for p in self.tag.contents:
                if getattr(p, '_node', None) is None:
                    continue

                if newChildHash == hash(p._node):
                    p.extract()

            # self.tag.contents.remove(newChild.tag)

        index = self.findChild(refChild)
        if index < 0 and not self.is_text(refChild):
            raise DOMException(DOMException.NOT_FOUND_ERR)

        if self.is_text(newChild):
            self.tag.insert(index, newChild.data.output_ready(formatter = lambda x: x))
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
        if index < 0:
            raise DOMException(DOMException.NOT_FOUND_ERR)

        if self.is_text(newChild):
            self.tag.contents[index] = newChild.data.output_ready(formatter = lambda x: x)
            return oldChild

        if newChild.nodeType in (Node.DOCUMENT_FRAGMENT_NODE, ):
            # self.tag.contents[index] = newChild.tag.findChild()
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
            oldChildHash = hash(oldChild.tag._node)

            for p in self.tag.contents:
                if getattr(p, '_node', None) is None:
                    continue

                if oldChildHash == hash(p._node):
                    p.extract()
            # self.tag.contents.remove(oldChild.tag)

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
            newChildHash = hash(newChild.tag._node)

            for p in self.tag.contents:
                if getattr(p, '_node', None) is None:
                    continue

                if newChildHash == hash(p._node):
                    p.extract()
            # self.tag.contents.remove(newChild.tag)

        if self.is_text(newChild):
            self.tag.append(newChild.data.output_ready(formatter = lambda x: x))
            return newChild

        if newChild.nodeType in (Node.DOCUMENT_FRAGMENT_NODE, ):
            # self.tag.append(newChild.tag.findChild())
            node = self.tag
            for p in newChild.tag.find_all_next():
                node.append(p)
                node = p

            return newChild

        self.tag.append(newChild.tag)
        return newChild

    def hasChildNodes(self):
        return len(self.tag.contents) > 0

    def _applyElement(self, element, where = 'inside'):
        where = where.lower()

        if where in ('inside', ):
            self.appendChild(element)

        if where in ('outside', ):
            self.insertBefore(element, self)

    # Modified in DOM Level 2
    def normalize(self):
        pass

    # Introduced in DOM Level 2
    def isSupported(self, feature, version):
        from .DOMImplementation import DOMImplementation
        return DOMImplementation.hasFeature(feature, version)

    # Introduced in DOM Level 2
    def hasAttributes(self):
        return self.attributes.length > 0

    # Introduced in DOM Level 3
    def _compareDocumentPosition(self, node):
        return None

    # @abstractmethod
    def cloneNode(self, deep):
        # Returns a duplicate of this node
        cloned = copy.copy(self)

        # The duplicate node has no parent (parentNode is null)
        cloned.tag.parent = None

        # Cloning an Element copies all attributes and their values but
        # this method does not copy any text it contains unless it is a
        # deep clone, since the Text is contained in a child Text node.
        if cloned.nodeType in (Node.ELEMENT_NODE, ) and deep is False:
            cloned.tag.string = ''

        # return cloned
        return self.wrap(self.doc, cloned.tag)

    @staticmethod
    def wrap(doc, obj):
        from .Element import Element

        if obj is None:
            return None

        if isinstance(obj, BeautifulSoup.CData):
            from .CDATASection import CDATASection
            return CDATASection(doc, obj)

        if isinstance(obj, BeautifulSoup.NavigableString):
            from .Text import Text
            return Text(doc, obj)

        return Element(doc, obj)
