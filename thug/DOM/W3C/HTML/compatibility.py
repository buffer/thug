#!/usr/bin/env python

import sys

if sys.version_info.major >= 3:
    thug_long = int
    thug_maxint = sys.maxsize
else:
    thug_long = long
    thug_maxint = sys.maxint
