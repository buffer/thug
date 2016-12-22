#!/usr/bin/env python

import logging
from .UIEvent import UIEvent

log = logging.getLogger("Thug")


# Introduced in DOM Level 2
class MouseEvent(UIEvent):
    MouseEventTypes = ('click', 'mousedown', 'mouseup', 'mouseover', 'mousemove', 'mouseout')

    def __init__(self, typeArg, target):
        UIEvent.__init__(self, typeArg, target)
        canBubbleArg  = typeArg in ('click', 'mousedown', 'mouseup', 'mouseover', 'mousemove', 'mouseout')
        cancelableArg = typeArg in ('click', 'mousedown', 'mouseup', 'mouseover', 'mouseout')
        self.initMouseEvent(typeArg          = typeArg,
                            canBubbleArg     = canBubbleArg,
                            cancelableArg    = cancelableArg,
                            relatedTargetArg = target)

    @property
    def altKey(self):
        return self._altKey

    @property
    def button(self):
        return self._button

    @property
    def clientX(self):
        return self._clientX

    @property
    def clientY(self):
        return self._clientY

    @property
    def ctrlKey(self):
        return self._ctrlKey

    @property
    def metaKey(self):
        return self._metaKey

    @property
    def relatedTarget(self):
        return self._relatedTarget

    @property
    def screenX(self):
        return self._screenX

    @property
    def screenY(self):
        return self._screenY

    @property
    def shiftKey(self):
        return self._shiftKey

    @property
    def detail(self):
        return self._detail

    def initMouseEvent(self,
                       typeArg,
                       canBubbleArg,
                       cancelableArg,
                       viewArg            = None,
                       detailArg          = 1,
                       screenXArg         = 0,
                       screenYArg         = 0,
                       clientXArg         = 0,
                       clientYArg         = 0,
                       ctrlKeyArg         = False,
                       altKeyArg          = False,
                       shiftKeyArg        = False,
                       metaKeyArg         = False,
                       buttonArg          = 1,
                       relatedTargetArg   = None):
        log.debug('initMouseEvent(%s, %s, %s, %s, %s)', typeArg,
                                                        canBubbleArg,
                                                        cancelableArg,
                                                        viewArg,
                                                        detailArg)

        self._screenX       = screenXArg
        self._screenY       = screenYArg
        self._clientX       = clientXArg
        self._clientY       = clientYArg
        self._ctrlKey       = ctrlKeyArg
        self._altKey        = altKeyArg
        self._shiftKey      = shiftKeyArg
        self._metaKey       = metaKeyArg
        self._button        = buttonArg
        self._relatedTarget = relatedTargetArg
        self.initUIEvent(typeArg, canBubbleArg, cancelableArg, viewArg, detailArg)
