#!/usr/bin/env python
#
# MimeTypes.py
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
from .MimeType import MimeType
from .Plugin import Plugin

log = logging.getLogger("Thug")

class MimeTypes(dict):
    def __init__(self):
        self['application/pdf'] = MimeType({   
                                            'description'   : 'Adobe Acrobat Plug-In',
                                            'suffixes'      : 'pdf',
                                            'type'          : 'application/pdf',
                                            'enabledPlugin' : Plugin({'name'        : 'Adobe Acrobat %s' % (log.ThugVulnModules.acropdf_pdf, ),
                                                                      'version'     : '%s' % (log.ThugVulnModules.acropdf_pdf, ),
                                                                      'description' : 'Adobe Acrobat Plug-In'}), 
                                            'enabled'       : True})  

        self['application/x-shockwave-flash'] = MimeType({  
                                            'description'   : 'Shockwave Flash',
                                            'suffixes'      : 'swf',
                                            'type'          : 'application/x-shockwave-flash',
                                            'enabledPlugin' : Plugin({'name'        : 'Shockwave Flash %s' % (log.ThugVulnModules.shockwave_flash, ),
                                                                      'version'       : '%s' % (log.ThugVulnModules.shockwave_flash, ),
                                                                      'description'   : 'Shockwave Flash %s' % (log.ThugVulnModules.shockwave_flash, ),}), 
                                            'enabled'       : True})

        if not log.ThugOpts.Personality.isWindows():
            return 
                    
        self['application/x-ms-wmz'] = MimeType({   
                                            'description'   : 'Windows Media Player',
                                            'suffixes'      : 'wmz',
                                            'type'          : 'application/x-ms-wmz',
                                            'enabledPlugin' : Plugin({'name'        : 'Windows Media Player 7',
                                                                      'version'       : '7',
                                                                      'description'   : 'Windows Media Player 7',}), 
                                            'enabled'       : True})  

    def __getitem__(self, key):
        try:
            key = int(key)
            return self.item(key)
        except:
            return dict.__getitem__(self, key) if key in self else MimeType()

    @property
    def length(self):
        return len(self)

    def item(self, index):
        if index >= self.length:
            return MimeType()

        return self.values()[index]

    def namedItem(self, name):
        return dict.__getitem__(self, key) if key in self else MimeType()
