#!/usr/bin/env python

from .Node import Node
from .DOMException import DOMException


class CharacterData(Node):
    def __init__(self, doc, tag):
        self.tag = tag
        self.tag._node = self
        Node.__init__(self, doc)

    def __str__(self):
        return str(self.tag)

    def getData(self):
        return self.tag

    def setData(self, data):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    data = property(getData, setData)

    @property
    def length(self):
        return len(self.data)

    def substringData(self, offset, count):
        return self.data[offset:offset + count]

    def appendData(self, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    def insertData(self, offset, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    def deleteData(self, offset, count):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    def replaceData(self, offset, count, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)
