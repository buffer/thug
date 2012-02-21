#!/usr/bin/env python
from __future__ import with_statement

# Introduced in DOM Level 2
class Event:
    CAPTURING_PHASE     = 1 # The current event phase is the capturing phase.
    AT_TARGET           = 2 # The event is currently being evaluated at the target EventTarget
    BUBBLING_PHASE      = 3 # The current event phase is the bubbling phase.

    def __init__(self):
        pass

    @property
    def type(self):
        return None

    @property
    def target(self):
        return None

    @property
    def currentTarget(self):
        return None

    @property
    def eventPhase(self):
        pass

    @property
    def bubbles(self):
        return False

    @property
    def cancelable(self):
        return False

    @property
    def timeStamp(self):
        return None

    def stopPropagation(self):
        pass

    def preventDefault(self):
        pass

    def initEvent(self, eventTypeArg, canBubbleArg, cancelableArg):
        pass

