#!/usr/bin/env python
from thug.DOM.W3C.DOMException import DOMException

# Introduced in DOM Level 2
class DocumentEvent(object):
    def __init__(self, doc):
        self.doc = doc

    def createEvent(self, eventType):
        raise DOMException(DOMException.NOT_SUPPORTED_ERR)
