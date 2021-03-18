#!/usr/bin/env python
from thug.DOM.W3C.Core.DOMException import DOMException

from .HTMLEvent import HTMLEvent
from .MouseEvent import MouseEvent
from .MutationEvent import MutationEvent
from .StorageEvent import StorageEvent
from .UIEvent import UIEvent


EventMap = {
    "HTMLEvent"      : HTMLEvent,
    "HTMLEvents"     : HTMLEvent,
    "MouseEvent"     : MouseEvent,
    "MouseEvents"    : MouseEvent,
    "MutationEvent"  : MutationEvent,
    "MutationEvents" : MutationEvent,
    "StorageEvent"   : StorageEvent,
    "UIEvent"        : UIEvent,
    "UIEvents"       : UIEvent
}


# Introduced in DOM Level 2
class DocumentEvent:
    def __init__(self, doc):
        self.doc = doc

    def createEvent(self, eventType):
        if eventType not in EventMap:
            raise DOMException(DOMException.NOT_SUPPORTED_ERR)

        return EventMap[eventType]()
