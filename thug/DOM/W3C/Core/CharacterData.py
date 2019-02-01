#!/usr/bin/env python

from .Node import Node
from .DOMException import DOMException


class CharacterData(Node):
    def __init__(self, doc, tag):
        self.tag = tag
        self.tag._node = self
        Node.__init__(self, doc)

    def getData(self):
        return self._data

    def setData(self, data):
        self._data = data

    data = property(getData, setData)

    @property
    def length(self):
        return len(self.data)

    def substringData(self, offset, count):
        return self.data[offset:offset + count]

    def appendData(self, arg):
        self.data += arg

    def insertData(self, offset, arg):
        if offset > len(self.data):
            raise DOMException(DOMException.INDEX_SIZE_ERR)

        self.data = self.data[:offset] + arg + self.data[offset:]

    def deleteData(self, offset, count):
        length = len(self.data)

        if offset > length:
            raise DOMException(DOMException.INDEX_SIZE_ERR)

        if offset + count > length:
            self.data = self.data[:offset]
        else:
            self.data = self.data[:offset] + self.data[offset + count:]

    def replaceData(self, offset, count, arg):
        s = self.data[:offset] + arg + self.data[offset + count:]
        self.data = s
