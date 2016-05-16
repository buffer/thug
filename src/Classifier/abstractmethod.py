#!/usr/bin/env python
#
# abstractmethod.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import sys

class abstractmethod(object):
    def __init__(self, func):
        self.func = func

    def __call__(self, *args, **kwds):
        func_name = self.func.__name__ if sys.version_info.major >= 3 else self.func.func_name
        raise NotImplementedError("method %s is abstract." % func_name)
