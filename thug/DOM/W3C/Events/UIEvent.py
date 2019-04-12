#!/usr/bin/env python

from .Event import Event


# Introduced in DOM Level 2
class UIEvent(Event):
    EventTypes = ('DOMFocusIn', 'DOMFocusOut', 'DOMActivate')

    def __init__(self):
        Event.__init__(self)
        self._view   = None
        self._detail = 0

    @property
    def view(self):
        return self._view

    @property
    def detail(self):
        return self._detail

    def initUIEvent(self, eventTypeArg, canBubbleArg, cancelableArg, viewArg = None, detailArg = 0):
        self.initEvent(eventTypeArg, canBubbleArg, cancelableArg)

        self._view       = viewArg
        self._detail     = detailArg
