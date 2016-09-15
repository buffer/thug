#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")

# Introduced in DOM Level 2
class EventListener(object):
    def __init__(self):
        pass

    def handleEvent(self, evt):
        log.debug('handleEvent(%s)', evt)
