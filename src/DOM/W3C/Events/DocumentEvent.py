#!/usr/bin/env python
from DOMException import DOMException

# Introduced in DOM Level 2
class DocumentEvent:
    def __init__(self, doc):
        self.doc = doc

    def createEvent(self, eventType):
        raise DOMException(DOMException.NOT_SUPPORTED_ERR)
