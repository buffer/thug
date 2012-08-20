#!/usr/bin/env python
#
# Plugin.py
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


class Plugin(dict):
    """A dictionary with attribute-style access. It maps attribute access to
    the real dictionary.  """
    def __init__(self, init = {}):
        dict.__init__(self, init)

    def __getstate__(self):
        return self.__dict__.items()

    def __setstate__(self, items):
        for key, val in items:
            self.__dict__[key] = val

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, dict.__repr__(self))

    def __setitem__(self, key, value):
        return super(Plugin, self).__setitem__(key, value)

    def __getitem__(self, name):
        return super(Plugin, self).__getitem__(name)

    def __delitem__(self, name):
        return super(Plugin, self).__delitem__(name)

    __getattr__ = __getitem__
    __setattr__ = __setitem__


ShockwaveFlashPlugin = Plugin({'name'        : 'Shockwave Flash',
                               'filename'    : 'C:\\WINDOWS\\system32\\Macromed\\Flash\\NPSWF32.dll',
                               'description' : 'Shockwave Flash 10.0 r42'})

AdobeAcrobatPlugin   = Plugin({'name'        : 'Adobe Acrobat',
                               'filename'    : 'C:\\Program Files\\Internet Explorer\\PLUGINS\\nppdf32.dll',
                               'description' : 'Adobe Acrobat Plug-In'})

AdobePDFPlugin       = Plugin({'name'        : 'Adobe PDF',
                               'filename'    : 'C:\\Program Files\\Internet Explorer\\PLUGINS\\nppdf32.dll',
                               'description' : 'Adobe PDF Plug-In'})

JavaPlugin           = Plugin({'name'        : 'Java(tm) Plug-In 2 SSV Helper',
                               'filename'    : 'C:\\Program Files\\\Java\\jre6\\bin\\jp2ssv.dll',
                               'description' : 'Java(tm) Plug-In 2 SSV Helper'})

Plugins = [
            ShockwaveFlashPlugin,
            AdobeAcrobatPlugin,
            AdobePDFPlugin,
            JavaPlugin
          ]
