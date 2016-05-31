#!/usr/bin/env python

from .Event import Event

import logging
log = logging.getLogger("Thug")

# Introduced in DOM Level 2

class StorageEvent(Event):
    StorageEventTypes = ('storage', )

    def __init__(self, eventTypeArg, target):
        Event.__init__(self, target)

    def initStorageEvent(self, 
                         eventTypeArg, 
                         canBubbleArg, 
                         cancelableArg,
                         keyArg,
                         oldValueArg,
                         newValueArg,
                         urlArg,
                         storageAreaArg):
        self._type       = eventTypeArg
        self.typeArg     = eventTypeArg
        self._canBubble  = canBubbleArg
        self._cancelable = cancelableArg
        self.key         = keyArg
        self.oldValue    = oldValueArg
        self.newValue    = newValueArg
        self.url         = urlArg
        self.storageArea = storageAreaArg
