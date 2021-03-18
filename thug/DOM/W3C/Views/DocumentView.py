#!/usr/bin/env python


# Introduced in DOM Level 2
class DocumentView:
    def __init__(self, doc):
        self.doc = doc

    @property
    def defaultView(self):
        return getattr(self, 'window', None)
