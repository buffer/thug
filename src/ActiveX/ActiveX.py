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
ActiveXAcct = dict()
modules     = []

log = logging.getLogger("Thug.ActiveX.ActiveX")

class ActiveXRecord:
    MAX_ARG_LENGTH = 50

    def __init__(self, cls, type):
        self.cls    = cls
        self.type   = type
        self.alerts = set()
        self.events = []
        
    def check_length(self, length):
        return length > self.MAX_ARG_LENGTH

    def check_for_url(self, value):
        return value.lower().find('http://') != -1
    
    def check_for_path(self, value):
        return value.lower().find('c:\\') != -1

    def setattr_checks(self, value):
        if self.check_length(len(value)):
            log.warning("[Attribute %s Length: %d]" % (name, len(value), ))
        if self.check_for_url(value):
            log.warning("[Attribute %s contains URL: %s]" % (name, value, ))
        if self.check_for_path(value):
            log.warning("[Attribute %s contains filename: %s]" % (name, value, ))

    def nosuchmethod_checks(self, name, arg):
        log.warning("[Function: %s [Argument: %d]" % (name, arg,))

        if self.check_length(len(arg)):
            log.warning("Function: %s [Argument length: %d]" % (name, len(arg), ))
        if self.check_for_url(arg):
            log.warning("Function: %s [URL in argument: %s]" % (name, arg, ))
        if self.check_for_path(arg):
            log.warning("Function: %s [Filename in argument: %s]" % (name, arg, ))

    def add_event_get(self, args):
        eventlog = 'ActiveXObject: GET ' + args[0]
        self.events.append(eventlog)

    def add_event_set(self, args):
        eventlog = 'ActiveXObject: SET ' + args[0] + ' = ' + str(args[1])
        self.events.append(eventlog)

    def add_event_call(self, args):
        eventlog = 'ActiveXObject: CALL ' + str(args[0])
        self.events.append(eventlog)

    def add_event(self, evttype, *args):
        m = getattr(self, 'add_event_%s' % (evttype), None)
        if not m:
            log.warning("Unknown ActiveX Event: %s" % (evttype, ))
            return

        m(args)

    def add_alert(self, alert):
        log.warning(alert)
        self.alerts.add(alert)


class _ActiveXObject:
    def __init__(self, cls, type = 'name'):
        ActiveXAcct[self] = ActiveXRecord(cls, type)
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

    def __setattr__(self, name, val):
        acct = ActiveXAcct[self]
        acct.add_event('set', name, val)

        self.__dict__[name] = val
        module              = modules[-1]
        key                 = "%s@%s" % (name, module, )

        if key in Attr2Fun.keys():
            Attr2Fun[name](val)
            return
        
        acct.setattr_checks(str([val]))

    def __call__(self, *args):
        acct = ActiveXAcct[self]
        acct.add_event('call', args)
        return self
        
    def __noSuchMethod__(self, name, *args):
        acct = ActiveXAcct[self]
        acct.add_event('call', args)

        for arg in args:
            if not isinstance(arg, (str, )):
                continue

            acct.nosuchmethod_checks(name, arg)

    def __load_module(self, module):
        script = ''
        with open(module, 'r') as fd:
            script = fd.read()
        return script

# DEPRECATED 
def add_alert(alert):
    #acct = ActiveXAcct[-1][1]
    #acct.alerts.add(alert)
    log.warning(alert)


# DEPRECATED
def write_log(md5, filename):
    if not eventlist:
        return

    logfile = 'log/%s/%s' % (md5, filename, )
    with open(logfile, 'wb') as fd:
        for log in eventlist: 
            fd.write(log + '\n')
        log.warning("Log saved into %s" % (logfile, ))
