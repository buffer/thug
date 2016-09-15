#!/usr/bin/env python

import logging

log = logging.getLogger("Thug")

# Introduced in DOM Level 2
class AbstractView(object):
    def __init__(self):
        pass

    @property
    def document(self):
        return None
