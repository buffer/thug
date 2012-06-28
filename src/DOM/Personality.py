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

import logging
log = logging.getLogger("Thug")

class Personality(dict):
    def __init__(self):
        # Windows XP personalities
        self['winxpie60'] = {
                "id"              : 1,
                "description"     : "Internet Explorer 6.0 (Windows XP)",
                "version"         : "6.0",
                "userAgent"       : "Mozilla/4.0 (Windows;  MSIE 6.0;  Windows NT 5.1;  SV1; .NET CLR 2.0.50727)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "4.0 (Windows;  MSIE 6.0;  Windows NT 5.1;  SV1; .NET CLR 2.0.50727)",
                "appMinorVersion" : ";SP2;",
                "platform"        : "Win32",
                "browserTag"      : "ie60",
                }

        self['winxpie61'] = { 
                "id"              : 2,
                "description"     : "Internet Explorer 6.1 (Windows XP)", 
                "version"         : "6.1",
                "userAgent"       : "Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
                "appMinorVersion" : ";SP2;",
                "platform"        : "Win32",
                "browserTag"      : "ie61",
                }

        self['winxpie70'] = {
                "id"              : 3,
                "description"     : "Internet Explorer 7.0 (Windows XP)",
                "version"         : "7.0",
                "userAgent"       : "Mozilla/4.0 (Windows; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "4.0 (Windows; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
                "appMinorVersion" : ";SP2;",
                "platform"        : "Win32",
                "browserTag"      : "ie70",
                }

        self['winxpie80'] = {
                "id"              : 4,
                "description"     : "Internet Explorer 8.0 (Windows XP)",
                "version"         : "8.0",
                "userAgent"       : "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; (R1 1.5); .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; (R1 1.5); .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
                "appMinorVersion" : ";SP2;",
                "platform"        : "Win32",
                "browserTag"      : "ie80",
                }

        # Windows 2000 personalities
        self['win2kie60'] = {
                "id"              : 5,
                "description"     : "Internet Explorer 6.0 (Windows 2000)",
                "version"         : "6.0",
                "userAgent"       : "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
                "appMinorVersion" : ";SP2;",
                "platform"        : "Win32",
                "browserTag"      : "ie60",
                }

        self['win2kie80'] = {
                "id"              : 6,
                "description"     : "Internet Explorer 8.0 (Windows 2000)",
                "version"         : "8.0",
                "userAgent"       : "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)",
                "appMinorVersion" : ";SP2;",
                "platform"        : "Win32",
                "browserTag"      : "ie80",
                }

        # MacOS X personalities
        self['osx10safari5'] = {
                "id"              : 7,
                "description"     : "Safari 5.1.1 (MacOS X 10.7.2)",
                "version"         : "5.1.1",
                "userAgent"       : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/534.51.22 (KHTML, like Gecko) Version/5.1.1 Safari/534.51.22",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/534.51.22 (KHTML, like Gecko) Version/5.1.1 Safari/534.51.22",
                "appMinorVersion" : None,
                "platform"        : "MacIntel",
                "browserTag"      : "safari5",
                }  

    @property
    def browserVersion(self):
        return self[log.ThugOpts.useragent]['version']

    def isIE(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('ie')

    def isFirefox(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('firefox')

    def isSafari(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('safari')

