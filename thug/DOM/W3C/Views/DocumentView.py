#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")


# Introduced in DOM Level 2
class DocumentView(object):
    def __init__(self, doc):
        self.doc = doc

    @property
    def defaultView(self):
        # return None
        return getattr(self, 'window', None)
