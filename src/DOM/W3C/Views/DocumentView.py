#!/usr/bin/env python
from __future__ import with_statement

import logging

log = logging.getLogger("Thug")

# Introduced in DOM Level 2
class DocumentView:
    def __init__(self):
        pass

    @property
    def defaultView(self):
        return None
