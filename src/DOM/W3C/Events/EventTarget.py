#!/usr/bin/env python
from __future__ import with_statement

import logging

log = logging.getLogger('Thug.DOM.W3C.Events.EventTarget')

# Introduced in DOM Level 2
class EventTarget:
    def addEventListener(self, eventType, listener, capture = False):
        log.warning('addEventListener(%s, \n%s, \n%s)' % (eventType, listener, capture, ))
        listener.__call__()

    def removeEventListener(self, eventType, listener, capture = False):
        log.warning('removeEventListener(%s, \n%s, \n%s)' % (eventType, listener, capture, ))
        listener.__call__()

    def dispatchEvent(self, evt):
        log.warning('dispatchEvent(%s)' % (evt, ))
        return True

