#!/usr/bin/env python

from .Event import Event


# Introduced in DOM Level 2
class HTMLEvent(Event):
    EventTypes = ('load',
                  'unload',
                  'abort',
                  'error',
                  'select',
                  'change',
                  'submit',
                  'reset',
                  'focus',
                  'blur',
                  'resize',
                  'scroll')

    def __init__(self):
        Event.__init__(self)
