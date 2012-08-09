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
                "description"     : "Internet Explorer 6.0\t(Windows XP)",
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
                "description"     : "Internet Explorer 6.1\t(Windows XP)", 
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
                "description"     : "Internet Explorer 7.0\t(Windows XP)",
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
                "description"     : "Internet Explorer 8.0\t(Windows XP)",
                "version"         : "8.0",
                "userAgent"       : "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; (R1 1.5); .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; (R1 1.5); .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
                "appMinorVersion" : ";SP2;",
                "platform"        : "Win32",
                "browserTag"      : "ie80",
                }

        self['winxpchrome20'] = {
                "id"              : 5,
                "description"     : "Chrome 20.0.1132.47\t(Windows XP)",
                "version"         : "20.0.1132.47",
                "userAgent"       : "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Windows NT 5.1) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
                "appMinorVersion" : None,
                "platform"        : "Win32",
                "browserTag"      : "chrome20",
                }   

        self['winxpfirefox12'] = {
                "id"              : 6,
                "description"     : "Firefox 12.0\t\t(Windows XP)",
                "version"         : "12.0",
                "userAgent"       : "Mozilla/5.0 (Windows NT 5.1; rv:12.0) Gecko/20120403211507 Firefox/12.0",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "12.0 (Windows)",
                "appMinorVersion" : None,
                "platform"        : "Win32",
                "browserTag"      : "firefox12",
                }

        self['winxpsafari5'] = {
                "id"              : 7,
                "description"     : "Safari 5.1.7\t\t(Windows XP)",
                "version"         : "5.1.7",
                "userAgent"       : "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Windows NT 5.1) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
                "appMinorVersion" : None,
                "platform"        : "Win32",
                "browserTag"      : "safari5",
                }   

        # Windows 2000 personalities
        self['win2kie60'] = {
                "id"              : 8,
                "description"     : "Internet Explorer 6.0\t(Windows 2000)",
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
                "id"              : 9,
                "description"     : "Internet Explorer 8.0\t(Windows 2000)",
                "version"         : "8.0",
                "userAgent"       : "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "5.0 (compatible; MSIE 8.0; Windows NT 5.0; Trident/4.0; InfoPath.1; SV1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 3.0.04506.30)",
                "appMinorVersion" : ";SP2;",
                "platform"        : "Win32",
                "browserTag"      : "ie80",
                }

        # Windows 7 personalities
        self['win7ie80'] = { 
                "id"              : 10,
                "description"     : "Internet Explorer 8.0\t(Windows 7)",
                "version"         : "8.0",
                "userAgent"       : "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.2)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.2)",
                "appMinorVersion" : "0",
                "platform"        : "Win32",
                "browserTag"      : "ie80",
                }

        self['win7ie90'] = {
                "id"              : 11,
                "description"     : "Internet Explorer 9.0\t(Windows 7)",
                "version"         : "9.0",
                "userAgent"       : "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.2; BOIE9;ENUS)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Microsoft Internet Explorer",
                "appVersion"      : "5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.2; BOIE9;ENUS)",
                "appMinorVersion" : "0",
                "platform"        : "Win32",
                "browserTag"      : "ie90",
                }

        self['win7chrome20'] = {
                "id"              : 12,
                "description"     : "Chrome 20.0.1132.47\t(Windows 7)",
                "version"         : "20.0.1132.47",
                "userAgent"       : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
                "appMinorVersion" : None,
                "platform"        : "Win32",
                "browserTag"      : "chrome20",
                }

        self['win7safari5'] = {
                "id"              : 13,
                "description"     : "Safari 5.1.7\t\t(Windows 7)",
                "version"         : "5.1.7",
                "userAgent"       : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
                "appMinorVersion" : None,
                "platform"        : "Win32",
                "browserTag"      : "safari5",
                }

        # MacOS X personalities
        self['osx10safari5'] = {
                "id"              : 14,
                "description"     : "Safari 5.1.1\t\t(MacOS X 10.7.2)",
                "version"         : "5.1.1",
                "userAgent"       : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/534.51.22 (KHTML, like Gecko) Version/5.1.1 Safari/534.51.22",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/534.51.22 (KHTML, like Gecko) Version/5.1.1 Safari/534.51.22",
                "appMinorVersion" : None,
                "platform"        : "MacIntel",
                "browserTag"      : "safari5",
                }  


        self['osx10chrome19'] = {
                "id"              : 15,
                "description"     : "Chrome 19.0.1084.54\t(MacOS X 10.7.4)",
                "version"         : "19.0.1084.54",
                "userAgent"       : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.54 Safari/536.5",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.54 Safari/536.5",
                "appMinorVersion" : None,
                "platform"        : "MacIntel",
                "browserTag"      : "chrome20",
                }


    @property
    def browserVersion(self):
        return self[log.ThugOpts.useragent]['version']

    def isIE(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('ie')

    def isWindows(self):
        return log.ThugOpts.useragent.startswith('win')

    def isFirefox(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('firefox')

    def isSafari(self):
        return self[log.ThugOpts.useragent]['browserTag'].startswith('safari')

