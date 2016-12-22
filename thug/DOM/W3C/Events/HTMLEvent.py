#!/usr/bin/env python

from .Event import Event

import logging

log = logging.getLogger("Thug")


# Introduced in DOM Level 2
class HTMLEvent(Event):
    HTMLEventTypes = ('load',
                      'unload',
                      'abort',
                      'error',
                      'select',
                      'change',
                      'submit',
                      'reset',
                      'focus',
                      'blur',
                      'resize',
                      'scroll')

    def __init__(self, eventTypeArg, target):
        Event.__init__(self, target)
        canBubbleArg  = eventTypeArg in ('abort', 'error', 'select', 'change', 'submit', 'reset', 'resize', 'scroll')
        cancelableArg = eventTypeArg in ('submit', )
        self.initEvent(eventTypeArg, canBubbleArg, cancelableArg)

    def initEvent(self, eventTypeArg, canBubbleArg, cancelableArg):
        self._type       = eventTypeArg
        self._canBubble  = canBubbleArg
        self._cancelable = cancelableArg
