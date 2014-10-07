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
                "product"         : None,
                "productSub"      : None,
                "vendor"          : None,
                "vendorSub"       : None,
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/4.0 (Windows XP 5.1) Java/%s",
                "cc_on"           : {
                                        "_jscript_version" : "5.6",
                                    },
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
                "product"         : None,
                "productSub"      : None,
                "vendor"          : None,
                "vendorSub"       : None,
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/4.0 (Windows XP 5.1) Java/%s",
                "cc_on"           : {
                                        "_jscript_version" : "5.6",
                                    },
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
                "product"         : None,
                "productSub"      : None,
                "vendor"          : None,
                "vendorSub"       : None,
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/4.0 (Windows XP 5.1) Java/%s",
                "cc_on"           : {
                                        "_jscript_version" : "5.7",
                                    },
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
                "product"         : None,
                "productSub"      : None,
                "vendor"          : None,
                "vendorSub"       : None,
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/4.0 (Windows XP 5.1) Java/%s",
                "cc_on"           : {
                                        "_jscript_version" : "5.8",
                                    },
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
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/5.0 (Windows XP 5.1) Java/%s",
                "cc_on"           : None,
                "browserTag"      : "chrome20",
                }   

        self['winxpfirefox12'] = {
                "id"              : 6,
                "description"     : "Firefox 12.0\t\t(Windows XP)",
                "version"         : "12.0",
                "userAgent"       : "Mozilla/5.0 (Windows NT 5.1; rv:12.0) Gecko/20120403211507 Firefox/12.0",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Windows)",
                "appMinorVersion" : None,
                "platform"        : "Win32",
                "product"         : "Gecko",
                "productSub"      : "2010101",
                "vendor"          : "",
                "vendorSub"       : "",
                "oscpu"           : "Windows NT 5.1",
                "buildID"         : "20120403211507",
                "javaUserAgent"   : "Mozilla/5.0 (Windows XP 5.1) Java/%s",
                "cc_on"           : None,
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
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Apple Computer, Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/5.0 (Windows XP 5.1) Java/%s",
                "cc_on"           : None,
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
                "product"         : None,
                "productSub"      : None,
                "vendor"          : None,
                "vendorSub"       : None,
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/4.0 (Windows 2000 5.0) Java/%s",
                "cc_on"           : {
                                        "_jscript_version" : "5.6",
                                    },
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
                "product"         : None,
                "productSub"      : None,
                "vendor"          : None,
                "vendorSub"       : None,
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/5.0 (Windows 2000 5.0) Java/%s",
                "cc_on"           : {
                                        "_jscript_version" : "5.8",
                                    },
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
                "product"         : None,
                "productSub"      : None,
                "vendor"          : None,
                "vendorSub"       : None,
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/4.0 (Windows 7 6.1) Java/%s",
                "cc_on"           : {
                                        "_jscript_version" : "5.8",
                                    },
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
                "product"         : None,
                "productSub"      : None,
                "vendor"          : None,
                "vendorSub"       : None,
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/5.0 (Windows 7 6.1) Java/%s",
                "cc_on"           : {
                                        "_jscript_version" : "9",
                                    },
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
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/5.0 (Windows 7 6.1) Java/%s",
                "cc_on"           : None,
                "browserTag"      : "chrome20",
                }

        self['win7firefox3'] = {
                "id"              : 13,
                "description"     : "Firefox 3.6.13\t\t(Windows 7)",
                "version"         : "3.6.13",
                "userAgent"       : "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Windows)",
                "appMinorVersion" : None,
                "platform"        : "Win32",
                "product"         : "Gecko",
                "productSub"      : "2010101",
                "vendor"          : "",
                "vendorSub"       : "",
                "oscpu"           : "Windows NT 6.1",
                "buildID"         : "20101203",
                "javaUserAgent"   : "Mozilla/5.0 (Windows XP 6.1) Java/%s",
                "cc_on"           : None,
                "browserTag"      : "firefox3",
                }

        self['win7safari5'] = {
                "id"              : 14,
                "description"     : "Safari 5.1.7\t\t(Windows 7)",
                "version"         : "5.1.7",
                "userAgent"       : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
                "appMinorVersion" : None,
                "platform"        : "Win32",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Apple Computer, Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : "Mozilla/5.0 (Windows 7 6.1) Java/%s",
                "cc_on"           : None,
                "browserTag"      : "safari5",
                }

        # MacOS X personalities
        self['osx10safari5'] = {
                "id"              : 15,
                "description"     : "Safari 5.1.1\t\t(MacOS X 10.7.2)",
                "version"         : "5.1.1",
                "userAgent"       : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/534.51.22 (KHTML, like Gecko) Version/5.1.1 Safari/534.51.22",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Macintosh; Intel Mac OS X 10_7_2) AppleWebKit/534.51.22 (KHTML, like Gecko) Version/5.1.1 Safari/534.51.22",
                "appMinorVersion" : None,
                "platform"        : "MacIntel",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Apple Computer, Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "safari5",
                }  

        self['osx10chrome19'] = {
                "id"              : 16,
                "description"     : "Chrome 19.0.1084.54\t(MacOS X 10.7.4)",
                "version"         : "19.0.1084.54",
                "userAgent"       : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.54 Safari/536.5",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.54 Safari/536.5",
                "appMinorVersion" : None,
                "platform"        : "MacIntel",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome19",
                }

        # Linux personalities
        self['linuxchrome26'] = {
                "id"              : 17,
                "description"     : "Chrome 26.0.1410.19\t(Linux)",
                "version"         : "26.0.1410.19",
                "userAgent"       : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.19 Safari/537.31",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.19 Safari/537.31",
                "appMinorVersion" : None,
                "platform"        : "Linux x86_64",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome26",
                }

        self['linuxchrome30'] = { 
                "id"              : 18, 
                "description"     : "Chrome 30.0.1599.15\t(Linux)",
                "version"         : "30.0.1599.15",
                "userAgent"       : "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.15 Safari/537.36",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.15 Safari/537.36",
                "appMinorVersion" : None,
                "platform"        : "Linux x86_64",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "", 
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome30",
                }   

        self['linuxfirefox19'] = {
                "id"              : 19,
                "description"     : "Firefox 19.0\t\t(Linux)",
                "version"         : "19.0",
                "userAgent"       : "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 Firefox/19.0",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (X11)",
                "appMinorVersion" : None,
                "platform"        : "Linux x86_64",
                "product"         : "Gecko",
                "productSub"      : "20100101",
                "vendor"          : "",
                "vendorSub"       : "",
                "oscpu"           : "Linux x86_64",
                "buildID"         : "20130215130331",
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "firefox19",
                }

        # Android personalities
        self['galaxy2chrome18'] = {
                "id"              : 20,
                "description"     : "Chrome 18.0.1025.166\t(Samsung Galaxy S II, Android 4.0.3)",
                "version"         : "18.0.1025.166",
                "userAgent"       : "Mozilla/5.0 (Linux; Android 4.0.3; GT-I9100 Build/IML74K) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Linux; Android 4.0.3; GT-I9100 Build/IML74K) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19",
                "appMinorVersion" : None,
                "platform"        : "Linux armv71",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome18",
                }

        self['galaxy2chrome25'] = {
                "id"              : 21,
                "description"     : "Chrome 25.0.1364.123\t(Samsung Galaxy S II, Android 4.0.3)",
                "version"         : "25.0.1364.123",
                "userAgent"       : "Mozilla/5.0 (Linux; Android 4.0.3; GT-I9100 Build/IML74K) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.123 Mobile Safari/537.22",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Linux; Android 4.0.3; GT-I9100 Build/IML74K) AppleWebKit/537.22 (KHTML, like Gecko) Chrome/25.0.1364.123 Mobile Safari/537.22",
                "appMinorVersion" : None,
                "platform"        : "Linux armv71",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome25",
                }

        self['galaxy2chrome29'] = {
                "id"              : 22,
                "description"     : "Chrome 29.0.1547.59\t(Samsung Galaxy S II, Android 4.1.2)",
                "version"         : "29.0.1547.59",
                "userAgent"       : "Mozilla/5.0 (Linux; Android 4.1.2; GT-I9100 Build/JZO54K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.59 Mobile Safari/537.36",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Linux; Android 4.1.2; GT-I9100 Build/JZO54K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.59 Mobile Safari/537.36",
                "appMinorVersion" : None,
                "platform"        : "Linux armv71",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome29",
        }

        self['nexuschrome18'] = {
                "id"              : 23,
                "description"     : "Chrome 18.0.1025.133\t(Google Nexus, Android 4.0.4)",
                "version"         : "18.0.1025.133",
                "userAgent"       : "Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.133 Mobile Safari/535.19",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.133 Mobile Safari/535.19",
                "appMinorVersion" : None,
                "platform"        : "Linux armv71",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Google Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome18",
                }

        # iOS personalities
        self['ipadsafari7'] = { 
                "id"              : 24,
                "description"     : "Safari 7.0\t\t(iPad, iOS 7.0.4)",
                "version"         : "7.0",
                "userAgent"       : "Mozilla/5.0 (iPad; CPU OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (iPad; CPU OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53",
                "appMinorVersion" : None,
                "platform"        : "iPad",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Apple Computer, Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "safari7",
                }

        self['ipadsafari8'] = {
                "id"              : 25, 
                "description"     : "Safari 8.0\t\t(iPad, iOS 8.0.2)",
                "version"         : "8.0",
                "userAgent"       : "Mozilla/5.0 (iPad; CPU OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A405 Safari/600.1.4",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (iPad; CPU OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A405 Safari/600.1.4",
                "appMinorVersion" : None,
                "platform"        : "iPad",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Apple Computer, Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "safari8",
                }

        self['ipadchrome33'] = {
                "id"              : 26,
                "description"     : "Chrome 33.0.1750.21\t(iPad, iOS 7.1)",
                "version"         : "33.0.1750.21",
                "userAgent"       : "Mozilla/5.0 (iPad; CPU OS 7_1 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) CriOS/33.0.1750.21 Mobile/11D167 Safari/9537.53 (7C45F3C7-DC11-40F0-9B5B-AA4A771C0904)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (iPad; CPU OS 7_1 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) CriOS/33.0.1750.21 Mobile/11D167 Safari/9537.53 (7C45F3C7-DC11-40F0-9B5B-AA4A771C0904)",
                "appMinorVersion" : None,
                "platform"        : "iPad",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Apple Computer, Inc.",
                "vendorSub"       : "", 
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome33",
                } 

        self['ipadchrome35'] = {
                "id"              : 27,
                "description"     : "Chrome 35.0.1916.41\t(iPad, iOS 7.1.1)",
                "version"         : "35.0.1916.41",
                "userAgent"       : "Mozilla/5.0 (iPad; CPU OS 7_1_1 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) CriOS/35.0.1916.41 Mobile/11D201 Safari/9537.53 (000125)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (iPad; CPU OS 7_1_1 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) CriOS/35.0.1916.41 Mobile/11D201 Safari/9537.53 (000125)",
                "appMinorVersion" : None,
                "platform"        : "iPad",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Apple Computer, Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome35",
                }

        self['ipadchrome37'] = {
                "id"              : 28,
                "description"     : "Chrome 37.0.2062.52\t(iPad, iOS 7.1.2)",
                "version"         : "37.0.2062.52",
                "userAgent"       : "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) CriOS/37.0.2062.52 Mobile/11D257 Safari/9537.53 (000658)",
                "appCodeName"     : "Mozilla",
                "appName"         : "Netscape",
                "appVersion"      : "5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) CriOS/37.0.2062.52 Mobile/11D257 Safari/9537.53 (000658)",
                "appMinorVersion" : None,
                "platform"        : "iPad",
                "product"         : "Gecko",
                "productSub"      : "20030107",
                "vendor"          : "Apple Computer, Inc.",
                "vendorSub"       : "",
                "oscpu"           : None,
                "buildID"         : None,
                "javaUserAgent"   : None,
                "cc_on"           : None,
                "browserTag"      : "chrome37",
                }

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
