#!/usr/bin/env python

import logging

from .HTMLMediaElement import HTMLMediaElement

log = logging.getLogger("Thug")


class HTMLAudioElement(HTMLMediaElement):
    def __init__(self, doc, tag):
        HTMLMediaElement.__init__(self, doc, tag)
