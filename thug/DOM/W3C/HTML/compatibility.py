#!/usr/bin/env python

import sys

thug_long = int if sys.version_info.major >= 3 else long
thug_maxint = sys.maxsize if sys.version_info.major >= 3 else sys.maxint
