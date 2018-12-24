#!/usr/bin/env python
#
# JSEngine.py
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
import six.moves.configparser as ConfigParser

import PyV8

import thug
from thug.Debugger.V8Debugger import V8Debugger


log = logging.getLogger("Thug")


class JSEngine(object):
    def __init__(self, window = None):
        self.init_engine()
        self.init_context(window)
        self.init_scripts()
        self.init_symbols()

    def init_engine(self):
        conf_file = os.path.join(log.configuration_path, 'thug.conf')
        config = ConfigParser.ConfigParser()
        config.read(conf_file)
        self.engine = config.get('jsengine', 'engine')

    def init_v8_context(self, window):
        self._context = PyV8.JSContext(window, extensions = log.JSExtensions)
        PyV8.JSEngine.setStackLimit(10 * 1024 * 1024)

    def init_context(self, window):
        m = getattr(self, "init_{}_context".format(self.engine), None)
        if m:
            m(window)

    def init_v8_scripts_thug(self, ctxt):
        thug_js = os.path.join(thug.__configuration_path__, 'scripts', "thug.js")
        ctxt.eval(open(thug_js, 'r').read())

    def init_v8_scripts_storage(self, ctxt):
        if log.ThugOpts.Personality.browserMajorVersion < 8:
            storage_js = os.path.join(thug.__configuration_path__, 'scripts', "storage.js")
            ctxt.eval(open(storage_js, 'r').read())

    def init_v8_scripts_date(self, ctxt):
        if log.ThugOpts.Personality.browserMajorVersion < 9:
            date_js = os.path.join(thug.__configuration_path__, 'scripts', "date.js")
            ctxt.eval(open(date_js, 'r').read())

    def init_v8_hooks(self, ctxt):
        hooks_folder = os.path.join(thug.__configuration_path__, 'hooks')
        hooks = os.listdir(hooks_folder) if os.path.exists(hooks_folder) else list()
        for hook in sorted([h for h in hooks if h.endswith('.js')]):
            ctxt.eval(open(os.path.join(hooks_folder, hook), 'r').read())

        for hook in ('eval', 'write'):
            js = os.path.join(thug.__configuration_path__, 'scripts', '{}.js'.format(hook))
            if not os.path.exists(js):
                continue

            symbol = getattr(log.ThugLogging, '{}_symbol'.format(hook))
            ctxt.eval(open(js, 'r').read() % {'name': symbol[0], 'saved': symbol[1]})

    def init_v8_scripts(self):
        with self._context as ctxt:
            self.init_v8_scripts_thug(ctxt)

            if log.ThugOpts.Personality.isIE():
                self.init_v8_scripts_storage(ctxt)
                self.init_v8_scripts_date(ctxt)

            self.init_v8_hooks(ctxt)
            PyV8.JSEngine.collect()

    def init_scripts(self):
        m = getattr(self, "init_{}_scripts".format(self.engine), None)
        if m:
            m()

    def init_v8_symbols(self):
        self.JSDebugger = V8Debugger
        self.JSFunction = PyV8.JSFunction
        self.JSObject = PyV8.JSObject
        self.collect = PyV8.JSEngine.collect
        self.terminateAllThreads = PyV8.JSEngine.terminateAllThreads
        self.setStackLimit = PyV8.JSEngine.setStackLimit

    def init_symbols(self):
        m = getattr(self, "init_{}_symbols".format(self.engine), None)
        if m:
            m()

    @property
    def context(self):
        return self._context
