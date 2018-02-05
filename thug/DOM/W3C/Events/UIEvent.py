#!/usr/bin/env python

import logging

from .Event import Event

log = logging.getLogger("Thug")


# Introduced in DOM Level 2
class UIEvent(Event):
    UIEventTypes = ('DOMFocusIn', 'DOMFocusOut', 'DOMActivate')

    def __init__(self, typeArg, target):
        Event.__init__(self, target)
        canBubbleArg  = typeArg in ('DOMFocusIn', 'DOMFocusOut', 'DOMActivate')
        cancelableArg = typeArg in ('DOMActivate', )
        self.initUIEvent(typeArg, canBubbleArg, cancelableArg)

    @property
    def view(self):
        return self._view

    @property
    def detail(self):
        return self._detail

    def initUIEvent(self, typeArg, canBubbleArg, cancelableArg, viewArg = None, detailArg = 0):
        log.debug('initUIEvent(%s, %s, %s, %s, %s)', typeArg,
                                                     canBubbleArg,
                                                     cancelableArg,
                                                     viewArg,
                                                     detailArg)

        self.initEvent(typeArg, canBubbleArg, cancelableArg)
        self._view   = viewArg
        self._detail = detailArg
