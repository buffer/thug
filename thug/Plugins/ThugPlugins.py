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

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

import logging
from zope.interface.verify import verifyObject
from zope.interface.exceptions import BrokenImplementation
from thug.Plugins.IPlugin import IPlugin

log = logging.getLogger("Thug")

(
    PRE_ANALYSIS_PLUGINS, 
    POST_ANALYSIS_PLUGINS,
) = list(range(0, 2))

class ThugPlugins(object):
    phases = {
                PRE_ANALYSIS_PLUGINS  : 'ThugPluginsPre',
                POST_ANALYSIS_PLUGINS : 'ThugPluginsPost'
             }

    def __init__(self, phase, thug):
        self.phase = phase
        self.thug  = thug
        self.__init_config()

    def __init_config(self):
        self.plugins = set()
        config       = ConfigParser.ConfigParser()

        conf_file = os.path.join(log.configuration_path, 'plugins.conf')

        if not os.path.exists(conf_file):
            conf_file = os.path.join(log.configuration_path, 'plugins.conf.default')

        if not os.path.exists(conf_file):
            return

        config.read(conf_file)
        
        plugins = config.get(self.phases[self.phase], 'plugins')
        for plugin in plugins.split(','):
            self.plugins.add(plugin.strip())

    def __call__(self):
        self.run()

    def run(self):
        for source in self.plugins:
            module = __import__(source)
            components = source.split('.')[1:]
            for component in components:
                module = getattr(module, component)

            handler = getattr(module, "Handler", None)
            if handler:
                p = handler()
                try:
                    verifyObject(IPlugin, p)
                    p.run(self.thug, log)
                except BrokenImplementation as e:
                    log.warning("[%s] %s", source, e)
