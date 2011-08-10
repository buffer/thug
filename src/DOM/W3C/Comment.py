#!/usr/bin/env python
from __future__ import with_statement

from DOMException import DOMException
from CharacterData import CharacterData


class Comment(CharacterData):
    @property
    def nodeName(self):
        return "#comment"

