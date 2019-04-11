#!/usr/bin/env python

from .Event import Event


# Introduced in DOM Level 2
class StorageEvent(Event):
    EventTypes = ('storage', )

    def __init__(self):
        Event.__init__(self)
        self._key         = None
        self._oldValue    = None
        self._newValue    = None
        self._url         = None
        self._storageArea = None

    @property
    def key(self):
        return self._key

    @property
    def oldValue(self):
        return self._oldValue

    @property
    def newValue(self):
        return self._newValue

    @property
    def url(self):
        return self._url

    @property
    def storageArea(self):
        return self._storageArea

    def initStorageEvent(self, eventTypeArg, canBubbleArg, cancelableArg, keyArg, oldValueArg,
                         newValueArg, urlArg, storageAreaArg):

        self.initEvent(eventTypeArg, canBubbleArg, cancelableArg)
        self._key         = keyArg
        self._oldValue    = oldValueArg
        self._newValue    = newValueArg
        self._url         = urlArg
        self._storageArea = storageAreaArg
