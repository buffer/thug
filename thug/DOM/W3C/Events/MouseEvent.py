#!/usr/bin/env python

from .UIEvent import UIEvent


# Introduced in DOM Level 2
class MouseEvent(UIEvent):
    EventTypes = ('click',
                  'mousedown',
                  'mouseup',
                  'mouseover',
                  'mousemove',
                  'mouseout')

    def __init__(self):
        UIEvent.__init__(self)
        self._screenX       = None
        self._screenY       = None
        self._clientX       = None
        self._clientY       = None
        self._ctrlKey       = None
        self._altKey        = None
        self._shiftKey      = None
        self._metaKey       = None
        self._button        = None
        self._relatedTarget = None

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

    def initMouseEvent(self, typeArg, canBubbleArg, cancelableArg, viewArg = None, detailArg = 0,
                    screenXArg = 0, screenYArg = 0, clientXArg = 0, clientYArg = 0, ctrlKeyArg = False,
                    altKeyArg = False, shiftKeyArg = False, metaKeyArg = False, buttonArg = 0, relatedTargetArg = None):

        self.initUIEvent(typeArg, canBubbleArg, cancelableArg, viewArg, detailArg)

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
