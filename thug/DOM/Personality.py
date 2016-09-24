#!/usr/bin/env python
#
# Personality.py
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
import os
import json
import logging
log = logging.getLogger("Thug")

class Personality(dict):
    def __init__(self):
        personalities = log.personalities_path

        if personalities is None:
            log.warning("[CRITICAL] Thug personalities not found! Exiting")
            sys.exit(0)

        for root, _dir, files in os.walk(personalities): #pylint:disable=unused-variable
            for f in files:
                if not f.endswith('.json'):
                    continue

                name = f.split(".json")[0]
                with open(os.path.join(root, f)) as personality:
                    self[name] = json.load(personality)

    @property
    def userAgent(self):
        return self[log.ThugOpts.useragent]['userAgent']

    @property
    def javaUserAgent(self):
        return self[log.ThugOpts.useragent]['javaUserAgent']

    @property
    def browserVersion(self):
        return self[log.ThugOpts.useragent]['version']

    @property
    def browserMajorVersion(self):
        return int(self.browserVersion.split('.')[0])

    @property
    def cc_on(self):
        return self[log.ThugOpts.useragent]['cc_on']

    def isIE(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('ie')

    def isWindows(self):
        return log.ThugOpts.useragent.startswith('win')

    def isFirefox(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('firefox')

    def isChrome(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('chrome')

    def isSafari(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('safari')

    def isOpera(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('opera')

    def getShellVariable(self, variableName):
        return self[log.ThugOpts.useragent].get('shellVariables', dict()).get(variableName.strip("%"), '')

    def getSpecialFolder(self, folderName):
        return self[log.ThugOpts.useragent].get('specialFolders', dict()).get(folderName, '')
