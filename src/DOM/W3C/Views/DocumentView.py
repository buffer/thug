#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")

# Introduced in DOM Level 2
class DocumentView:
    def __init__(self):
        pass

    @property
    def defaultView(self):
        return None
