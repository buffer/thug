#!/usr/bin/env python
#
# Plugins.py
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


class Plugins(list):
    def __init__(self):
        list.__init__(self)

    @property
    def length(self):
        return len(self)

    def __getattr__(self, key):
        return self.namedItem(key)

    def __getitem__(self, key):
        try:
            key = int(key)
            return self.item(key)
        except ValueError:
            return self.namedItem(key)

    def item(self, index):
        if index >= self.length:
            return None

        return list.__getitem__(self, index)

    def namedItem(self, name):
        index = 0

        while index < self.length:
            p = self.item(index)
            if p['name'] == name:
                return p

            index += 1

        return None

    def refresh(self, reloadDocuments = False):
        pass
