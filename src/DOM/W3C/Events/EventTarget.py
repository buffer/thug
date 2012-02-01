#!/usr/bin/env python
from __future__ import with_statement

import logging

log = logging.getLogger("Thug")

# Introduced in DOM Level 2
class EventTarget:
    def addEventListener(self, eventType, listener, capture = False):
        log.debug('addEventListener(%s, \n%s, \n%s)' % (eventType, listener, capture, ))
        listener.__call__()

    def removeEventListener(self, eventType, listener, capture = False):
        log.debug('removeEventListener(%s, \n%s, \n%s)' % (eventType, listener, capture, ))
        listener.__call__()

    def dispatchEvent(self, evt):
        log.debug('dispatchEvent(%s)' % (evt, ))
        return True

