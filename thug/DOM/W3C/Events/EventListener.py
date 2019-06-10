#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")


# Introduced in DOM Level 2
class EventListener(object):
    def __init__(self): # pragma: no cover
        pass

    def handleEvent(self, evt): # pragma: no cover
        log.debug('handleEvent(%s)', evt)
