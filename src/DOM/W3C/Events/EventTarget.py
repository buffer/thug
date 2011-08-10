#!/usr/bin/env python
from __future__ import with_statement

import logging

# Introduced in DOM Level 2
class EventTarget:
    log = logging.getLogger('EventTarget')

    def addEventListener(self, eventType, listener, capture = False):
        self.log.warning('addEventListener(%s, \n%s, \n%s)' % (eventType, listener, capture, ))
        print type(listener)

    def removeEventListener(self, eventType, listener, capture = False):
        self.log.warning('removeEventListener(%s, \n%s, \n%s)' % (eventType, listener, capture, ))
        print type(listener)

    def dispatchEvent(self, evt):
        self.log.warning('dispatchEvent(%s)' % (evt, ))
        return True

