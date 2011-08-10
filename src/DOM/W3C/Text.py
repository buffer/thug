#!/usr/bin/env python
from __future__ import with_statement

import sys, re, string
import PyV8

from DOMException import DOMException
from CharacterData import CharacterData

class Text(CharacterData):
    def __repr__(self):
        return "<Text '%s' at 0x%08X>" % (self.tag, id(self))

    def splitText(self, offset):
        raise DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR)

    @property
    def nodeValue(self):
        return self.data

    @property
    def nodeName(self):
        return "#text"

