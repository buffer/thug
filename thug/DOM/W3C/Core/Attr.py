#!/usr/bin/env python

import bs4 as BeautifulSoup

from .Node import Node


class Attr(Node):
    _value = ""

    def __init__(self, doc, parent, attr):
        self.doc    = doc
        self.parent = parent
        self.attr   = attr
        self.tag    = BeautifulSoup.Tag(parser = self.doc, name = 'attr')
        Node.__init__(self, doc)

        self._specified = False
        self._value     = self.getValue()

    def __eq__(self, other):
        return hasattr(other, "parent") and self.parent == other.parent and \
               hasattr(other, "attr") and self.attr == other.attr

    @property
    def nodeType(self):
        return Node.ATTRIBUTE_NODE

    @property
    def nodeName(self):
        return self.attr

    def getNodeValue(self):
        return self.getValue()

    def setNodeValue(self, value):
        self.setValue(value)

    nodeValue = property(getNodeValue, setNodeValue)

    @property
    def childNodes(self):
        from .NodeList import NodeList
        return NodeList(self.doc, [])

    @property
    def parentNode(self):
        return self.parent

    # Introduced in DOM Level 2
    @property
    def ownerElement(self):
        if self.parent:
            if self.parent.nodeType == Node.ELEMENT_NODE:
                return self.parent

        return None

    @property
    def ownerDocument(self):
        return self.parent.doc

    @property
    def name(self):
        return self.attr

    @property
    def specified(self):
        if self.ownerElement is None:
            return True

        return self._specified

    def getValue(self):
        if self.parent:
            if self.parent.tag.has_attr(self.attr):
                self._specified = True
                return self.parent.tag[self.attr]

        return self._value

    def setValue(self, value):
        self._value = value

        if self.parent:
            self._specified = True
            self.parent.tag[self.attr] = value

    value = property(getValue, setValue)
