#!/usr/bin/env python

from .Event import Event


# Introduced in DOM Level 2
class MutationEvent(Event):
    MODIFICATION = 1  # The Attr was just added
    ADDITION     = 2  # The Attr was modified in place
    REMOVAL      = 3  # The Attr was just removed

    @property
    def relatedNode(self):
        return None

    @property
    def prevValue(self):
        return None

    @property
    def newValue(self):
        return None

    @property
    def attrName(self):
        return None

    @property
    def attrChange(self):
        return None

    def initMutationEvent(self, typeArg,
                                canBubbleArg,
                                cancelableArg,
                                relatedNodeArg,
                                prevValueArg,
                                newValueArg,
                                attrNameArg,
                                attrChangeArg):
        pass
