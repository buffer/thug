#!/usr/bin/env python
from __future__ import with_statement

import logging

log = logging.getLogger("Thug")

# Introduced in DOM Level 2
class EventListener:
    def __init__(self):
        pass

    def handleEvent(self, evt):
        log.debug('handleEvent(%s)' % (evt, ))

