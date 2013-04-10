#!/usr/bin/env python

import sys

if sys.version_info.major >= 3:
    thug_string  = str
    thug_unicode = str
else:
    thug_string  = basestring
    thug_unicode = unicode
