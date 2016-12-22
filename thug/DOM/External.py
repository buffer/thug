#!/usr/bin/env python
#
# External.py
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

import logging

log = logging.getLogger("Thug")


class External(object):
    def __init__(self):
        self._providers = set()
        self._channels  = set()
        self._favorites = set()

        self.__init_personality()

    def __init_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_personality_IE()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_personality_Chrome()

    def __init_personality_IE(self):
        self.frozen               = self._frozen
        self.menuArguments        = self._menuArguments
        self.AddDesktopComponent  = self._AddDesktopComponent
        self.AddFavorite          = self._AddFavorite
        self.AutoCompleteSaveForm = self._AutoCompleteSaveForm
        self.AutoScan             = self._AutoScan
        self.bubbleEvent          = self._bubbleEvent
        self.IsSubscribed         = self._IsSubscribed
        self.NavigateAndFind      = self._NavigateAndFind
        self.raiseEvent           = self._raiseEvent
        self.ShowBrowserUI        = self._ShowBrowserUI

        if log.ThugOpts.Personality.browserMajorVersion < 7:
            self.AddChannel = self._AddChannel

        if log.ThugOpts.Personality.browserMajorVersion >= 7:
            self.AddSearchProvider         = self._AddSearchProvider
            self.IsSearchProviderInstalled = self._IsSearchProviderInstalled

    def __init_personality_Chrome(self):
        self.AddSearchProvider = self._AddSearchProvider

    @property
    def _frozen(self):
        return False

    @property
    def _menuArguments(self):
        return None

    def _AddChannel(self, URL):
        self._channels.add(URL)

    def _AddDesktopComponent(self, URL, type, left = None, top = None, width = None, height = None):  # pylint:disable=redefined-builtin
        pass

    def _AddFavorite(self, URL, title = None):
        self._favorites.add((URL, title))

    def _AddSearchProvider(self, URL):
        self._providers.add(URL)

    def _AutoCompleteSaveForm(self, formElement):
        pass

    def _AutoScan(self, domainPart, defaultURL = None, target = None):
        # This method does not work in Internet Explorer from version 7
        # and raises an exception.
        if log.ThugOpts.Personality.browserMajorVersion >= 7:
            raise TypeError()

    def _bubbleEvent(self):
        pass

    def _IsSearchProviderInstalled(self, URL):
        if URL in self._providers:
            return 1  # A matching search provider is installed, but it is not the default.

        return 0    # No installed search provider was found with the specified prefix

    def _IsSubscribed(self, URL):
        return False

    def _NavigateAndFind(self, URL, textToFind, findInFrame):
        pass

    def _raiseEvent(self, eventName, eventObj):
        pass

    def _ShowBrowserUI(dialogBoxType, null = None):
        pass
