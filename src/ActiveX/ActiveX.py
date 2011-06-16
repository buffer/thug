#!/usr/bin/env python
#
# ActiveX.py
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


import os
import logging
from CLSID import *

ACTIVEX_MODULES = "ActiveX/modules/%s.py"
MAX_ARG_LENGTH  = 50

eventlist = []
modules   = []

log = logging.getLogger("ActiveX")

class _ActiveXObject:
    global opts

    def __init__(self, cls, type = 'name'):
        _module = None
        
        if type == 'id':
            if len(cls) > 5 and cls[:6].lower() == 'clsid:':
                cls = cls[6:].upper()
            if cls in clsidlist.keys(): 
                _module = clsidlist[cls]
        else:
            if cls in clsnamelist: 
                _module = clsnamelist[cls]
            
        if not _module:
            log.warning("Unknown ActiveX Object: %s" % (cls, ))
            return
            
        module = ACTIVEX_MODULES % (_module, )
        if not os.access(module, os.F_OK):
            log.warning("Unknown ActiveX Object: %s" % (cls, ))
            return

        modules.append(_module)
        exec self.__load_module(module)
    
    def __check_length(self, length):
        return length > MAX_ARG_LENGTH

    def __check_for_url(self, value):
        return value.lower().find('http://') != -1

    def __check_for_path(self, value):
        return value.lower().find('c:\\') != -1

    def __setattr__(self, name, val):
        self.__add_event('set', name, val)
        self.__dict__[name] = val
        module = modules[-1]
        key    = "%s@%s" % (name, module, )

        if key in Attr2Fun.keys():
            Attr2Fun[name](val)
            return
        
        value  = str([val])
        length = len(value)

        if self.__check_length(length):
            log.warning("[Attribute %s Length: %d]" % (name, length, ))
        if self.__check_for_url(value):
            log.warning("[Attribute %s contains URL: %s]" % (name, value, ))
        if self.__check_for_path(value):
            log.warning("[Attribute %s contains filename: %s]" % (name, value, ))

    def __call__(self, *args):
        self.__add_event('call', args)
        return self
        
    def __noSuchMethod__(self, name, *args):
        self.__add_event('call', args)

        for arg in args:
            if isinstance(arg, (str, )):
                log.warning("[Function: %s [Argument: %d]" % (name, arg,))
                if self.__check_length(len(arg)):
                    log.warning("Function: %s [Argument length: %d]" % (name, len(arg), ))
                if self.__check_for_url(arg):
                    log.warning("Function: %s [URL in argument: %s]" % (name, arg, ))
                if self.__check_for_path(arg):
                    log.warning("Function: %s [Filename in argument: %s]" % (name, arg, ))

    def __load_module(self, module):
        script = ''
        with open(module, 'r') as fd:
            script = fd.read()
        return script

    def __add_event(self, evttype, *args):
        eventlog = 'ActiveXObject: '
        if evttype == 'get': 
            eventlog += 'GET ' + args[0]
        if evttype == 'set': 
            eventlog += 'SET ' + args[0] + ' = ' + str(args[1])
        if evttype == 'call': 
            eventlog += 'CALL ' + str(args[0])
        eventlist.append(eventlog)

def add_alert(alert):
    log.warning(alert)

def write_log(md5, filename):
    if not eventlist:
        return

    logfile = 'log/%s/%s' % (md5, filename, )
    with open(logfile, 'wb') as fd:
        for log in eventlist: 
            fd.write(log + '\n')
        log.warning("Log saved into %s" % (logfile, ))
