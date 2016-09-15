#!/usr/bin/env python
#
# Encoding.py
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


from chardet.universaldetector import UniversalDetector

class Encoding(object):
    def __init__(self):
        self.detector = UniversalDetector()

    def _detect(self, data):
        self.detector.reset()
        self.detector.feed(data)
        self.detector.close()
        return self.detector.result

    def detect(self, data, safe = False):
        try:
            return self._detect(data)
        except:
            if safe:
                return None

            raise
