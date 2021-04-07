#!/usr/bin/env python

from thug.DOM.JSClass import JSClass


# Introduced in DOM Level 2
class EventException(RuntimeError, JSClass):
    UNSPECIFIED_EVENT_TYPE_ERR = 0  # If the Event's type was not specified by initializing the event before the
                                    # method was called. Specification of the Event's type as null or an empty
                                    # string will also trigger this exception.

    def __init__(self, code):
        super().__init__(code)
        self.code = code
