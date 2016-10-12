#!/usr/bin/env python
#
# ThugPlugins.py
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
import sys
import logging
from zope.interface.verify import verifyObject
from zope.interface.exceptions import BrokenImplementation
from thug.Plugins.IPlugin import IPlugin

log = logging.getLogger("Thug")

PLUGINS_PATH          = "/etc/thug/plugins"
HANDLER_NAME          = "Handler"
HANDLER_MODULE        = "%s.py" % (HANDLER_NAME, )
FIRST_LOW_PRIO        = 1000
PRE_ANALYSIS_PLUGINS  = 'PRE'
POST_ANALYSIS_PLUGINS = 'POST'

sys.path.append(PLUGINS_PATH)


class ThugPlugins(object):
    def __init__(self, phase, thug):
        self.phase            = phase
        self.thug             = thug
        self.plugins          = dict()
        self.last_low_prio    = FIRST_LOW_PRIO
        self.get_plugins()

    def __call__(self):
        self.run()

    def handle_low_prio_plugin(self):
        plugin_prio = self.last_low_prio
        self.last_low_prio += 1
        return plugin_prio

    def get_plugin_prio(self, plugin_info):
        if len(plugin_info) < 3:
            return self.handle_low_prio_plugin()

        try:
            plugin_prio = int(plugin_info[2])
        except:
            plugin_prio = self.handle_low_prio_plugin()

        return plugin_prio

    def get_plugins(self):
        plugins = dict()

        for p in os.listdir(PLUGINS_PATH):
            if not p.startswith(self.phase):
                continue

            pkg = os.path.join(PLUGINS_PATH, p)
            if not os.path.isdir(pkg):
                continue
        
            if not HANDLER_MODULE in os.listdir(pkg):
                continue

            plugin_info = p.split('-')
            if len(plugin_info) < 2:
                continue

            plugin_name = p
            plugin_prio = self.get_plugin_prio(plugin_info)

            plugins[plugin_name] = plugin_prio

        self.plugins = sorted(plugins.items(), key = lambda x: x[1])

    def run(self):
        for plugin in self.plugins:
            name, prio = plugin
            source = "%s.%s" % (name, HANDLER_NAME)

            module = __import__(source)
            components = source.split('.')[1:]
            for component in components:
                module = getattr(module, component)

            handler = getattr(module, "Handler", None)
            if handler:
                log.warning("[PLUGIN][%s] Phase: %s_ANALYSIS Priority: %d" % (name.split('-')[1],
                                                                              self.phase,
                                                                              prio))
                p = handler()
                try:
                    verifyObject(IPlugin, p)
                    p.run(self.thug, log)
                except BrokenImplementation as e:
                    log.warning("[%s] %s", source, e)
