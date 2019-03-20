#!/usr/bin/env python
#
# UserProfile.py
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

from .JSClass import JSClass


class UserProfile(JSClass):
    vCardSchemas = ("vCard.Business.City",
                    "vCard.Business.Country",
                    "vCard.Business.Fax",
                    "vCard.Business.Phone",
                    "vCard.Business.State",
                    "vCard.Business.StreetAddress",
                    "vCard.Business.URL",
                    "vCard.Business.Zipcode",
                    "vCard.Cellular",
                    "vCard.Company",
                    "vCard.Department",
                    "vCard.DisplayName",
                    "vCard.Email",
                    "vCard.FirstName",
                    "vCard.Gender",
                    "vCard.Home.City",
                    "vCard.Home.Country",
                    "vCard.Home.Fax",
                    "vCard.Home.Phone",
                    "vCard.Home.State",
                    "vCard.Home.StreetAddress",
                    "vCard.Home.Zipcode",
                    "vCard.Homepage",
                    "vCard.JobTitle",
                    "vCard.LastName",
                    "vCard.MiddleName",
                    "vCard.Notes",
                    "vCard.Office",
                    "vCard.Pager")

    def __init__(self):
        self._vCard = dict()
        self._queue = list()

    def addReadRequest(self, vCardName, reserved = None):
        for schema in self.vCardSchemas:
            if schema.lower() == vCardName.lower():
                self._queue.append(vCardName)
                return True

        return False

    def doReadRequest(self, usageCode,
                            displayName = None,
                            domain = None,
                            path = None,
                            expiration = None,
                            reserved = None):
        pass

    def clearRequest(self):
        del self._queue[:]

    def getAttribute(self, vCardName):
        if vCardName not in self.vCardSchemas:
            return None

        if vCardName not in self._vCard:
            return None

        return self._vCard[vCardName]

    def setAttribute(self, vCardName, vCardValue, caseSens = 1):
        if caseSens:
            if vCardName not in self.vCardSchemas:
                return

            self._vCard[vCardName] = vCardValue
            return

        for schema in self.vCardSchemas:
            if schema.lower() == vCardName.lower():
                self._vCard[schema] = vCardValue
                return
