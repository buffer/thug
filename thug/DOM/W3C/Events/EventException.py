#!/usr/bin/env python

from thug.DOM.JSClass import JSClass


# Introduced in DOM Level 2
class EventException(RuntimeError, JSClass):
    def __init__(self, code):
        self.code = code

    # Exception Code
    UNSPECIFIED_EVENT_TYPE_ERR = 0  # If the Event's type was not specified by initializing the event before the
                                    # method was called. Specification of the Event's type as null or an empty
                                    # string will also trigger this exception.
