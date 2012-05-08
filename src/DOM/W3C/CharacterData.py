#!/usr/bin/env python

import sys, re, string
import PyV8

from DOMException import DOMException
from Node import Node

class CharacterData(Node):
    def __init__(self, doc, tag):
        Node.__init__(self, doc)
        self.tag = tag

    def __str__(self):
        return str(self.tag)

    def getData(self):
        return unicode(self.tag)

    # FIXME
    def setData(self, data):
        self.tag = data
        #raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    data = property(getData, setData)

    @property
    def length(self):
        return len(self.tag)

    def substringData(self, offset, count):
        return self.tag[offset:offset+count]

    def appendData(self, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    def insertData(self, offset, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    def deleteData(self, offset, count):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    def replaceData(self, offset, count, arg):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

