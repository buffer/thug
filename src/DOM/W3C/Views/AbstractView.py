#!/usr/bin/env python
from __future__ import with_statement

import logging

log = logging.getLogger("Thug")

# Introduced in DOM Level 2
class AbstractView:
    def __init__(self):
        pass

    @property
    def document(self):
        return None
