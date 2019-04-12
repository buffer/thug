#!/usr/bin/env python

from .Event import Event


# Introduced in DOM Level 2
class MutationEvent(Event):
    MODIFICATION = 1  # The Attr was just added
    ADDITION     = 2  # The Attr was modified in place
    REMOVAL      = 3  # The Attr was just removed

    EventTypes = ('DOMSubtreeModified',
                  'DOMNodeInserted',
                  'DOMNodeRemoved',
                  'DOMNodeRemovedFromDocument',
                  'DOMNodeInsertedIntoDocument',
                  'DOMAttrModified',
                  'DOMCharacterDataModified')

    def __init__(self):
        Event.__init__(self)
        self._relatedNode = None
        self._prevValue   = None
        self._newValue    = None
        self._attrName    = None
        self._attrChange  = None

    @property
    def relatedNode(self):
        return self._relatedNode

    @property
    def prevValue(self):
        return self._prevValue

    @property
    def newValue(self):
        return self._newValue

    @property
    def attrName(self):
        return self._attrName

    @property
    def attrChange(self):
        return self._attrChange

    def initMutationEvent(self, eventTypeArg, canBubbleArg, cancelableArg, relatedNodeArg,
                        prevValueArg, newValueArg, attrNameArg, attrChangeArg):

        self.initEvent(eventTypeArg, canBubbleArg, cancelableArg)

        self._relatedNode = relatedNodeArg
        self._prevValue   = prevValueArg
        self._newValue    = newValueArg
        self._attrName    = attrNameArg
        self._attrChange  = attrChangeArg
