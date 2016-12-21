#!/usr/bin/env python
#
# ClipboardData.py
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


class ClipboardData(object):
    def __init__(self):
        self._data = dict()

    def getData(self, dataFormat):
        if dataFormat in self._data:
            return self._data[dataFormat]

        return None

    def setData(self, dataFormat, data):
        if dataFormat not in ('Text', 'URL'):
            return False

        self._data[dataFormat] = data
        return True

    def clearData(self, dataFormat = None):
        if dataFormat is None:
            self._data.clear()
            return

        if dataFormat in self._data:
            del self._data[dataFormat]
