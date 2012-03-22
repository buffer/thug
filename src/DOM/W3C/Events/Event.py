#!/usr/bin/env python
from __future__ import with_statement

# Introduced in DOM Level 2
class Event:
    CAPTURING_PHASE     = 1 # The current event phase is the capturing phase.
    AT_TARGET           = 2 # The event is currently being evaluated at the target EventTarget
    BUBBLING_PHASE      = 3 # The current event phase is the bubbling phase.

    def __init__(self, evt, target):
        self._evt          = evt
        self._target       = target
        self.currentTarget = target
        self.eventPhase    = self.AT_TARGET
        self._stop         = False
        self._prevent      = False

    @property
    def type(self):
        return self._evt

    @property
    def target(self):
        return self._target

    #@property
    #def currentTarget(self):
    #    return None

    #@property
    #def eventPhase(self):
    #    pass

    @property
    def bubbles(self):
        return False

    @property
    def cancelable(self):
        return False

    @property
    def timeStamp(self):
        return 0

    def stopPropagation(self):
        self._stop = True

    def preventDefault(self):
        self._prevent = True

    def initEvent(self, eventTypeArg, canBubbleArg, cancelableArg):
        pass

