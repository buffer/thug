#!/usr/bin/env python

from .DOMException import DOMException
from .Node import Node


class CharacterData(Node):
    def __init__(self, doc, data):
        self._data = data
        Node.__init__(self, doc)

    def __str__(self):
        return str(self.data)

    def getData(self):
        return self._data

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
