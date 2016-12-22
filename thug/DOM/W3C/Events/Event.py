#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")


# Introduced in DOM Level 2
class Event(object):
    CAPTURING_PHASE     = 1  # The current event phase is the capturing phase.
    AT_TARGET           = 2  # The event is currently being evaluated at the target EventTarget
    BUBBLING_PHASE      = 3  # The current event phase is the bubbling phase.

    def __init__(self, target):
        self._target             = target
        self.currentTarget       = target
        self.eventPhase          = self.AT_TARGET
        self._stoppedPropagation = False
        self._defaultPrevented   = False
        self._canBubble          = False
        self._cancelable         = False

        # Prior to IE9, IE does not support the stopPropagation() method. Instead,
        # the IE Event object has a property named `cancelBubble'. Setting this
        # property to true prevents any further propagation (IE8 and before do not
        # support the captuting phase of event propagation so bubbling is the only
        # kind of propagation to be canceled)
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
            self.cancelBubble = property(self._getPropagationStatus, self._setPropagationStatus)
        else:
            self.stopPropagation = self._stopPropagation

        # In IE prior to IE9 the default action can be canceled by setting the
        # `returnValue' of the Event object to false
        if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 9:
            self.returnValue = property(self._getDefaultPrevented, self._setDefaultPrevented)
        else:
            self.preventDefault = self._preventDefault

    def _getPropagationStatus(self):
        return self._stoppedPropagation

    def _setPropagationStatus(self, value):
        self._stoppedPropagation = True if value else False

    def _stopPropagation(self):
        self._stoppedPropagation = True

    def _getDefaultPrevented(self):
        return self._defaultPrevented

    def _setDefaultPrevented(self, value):
        self._defaultPrevented = True if value else False

    def _preventDefault(self):
        self._defaultPrevented = True

    @property
    def type(self):
        return self._type

    @property
    def target(self):
        return self._target

    @property
    def bubbles(self):
        return self._canBubble

    @property
    def cancelable(self):
        return self._cancelable

    @property
    def timeStamp(self):
        return 0

    def initEvent(self, eventTypeArg, canBubbleArg, cancelableArg):
        self._type       = eventTypeArg
        self._canBubble  = canBubbleArg
        self._cancelable = cancelableArg
