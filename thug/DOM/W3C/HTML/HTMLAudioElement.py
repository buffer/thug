#!/usr/bin/env python

from .HTMLMediaElement import HTMLMediaElement

import logging
log = logging.getLogger("Thug")


class HTMLAudioElement(HTMLMediaElement):
    def __init__(self, doc, tag):
        HTMLMediaElement.__init__(self, doc, tag)
