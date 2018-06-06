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


import cchardet


class Encoding(object):
    def detect(self, data, safe = False):
        try:
            return cchardet.detect(data)
        except TypeError:
            # TypeError is usually raised when cchardet expects a string
            # instead of unicode. Let's give it another last try before
            # giving up
            try:
                return cchardet.detect(str(data))
            except Exception:
                raise
        except Exception:  # pragma: no cover
            if safe:
                return None
            raise
