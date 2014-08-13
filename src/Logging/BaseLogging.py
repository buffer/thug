#!/usr/bin/env python
#
# BaseLogging.py
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
import errno
import hashlib
import datetime
import logging

log = logging.getLogger("Thug")

class BaseLogging(object):
    def __init__(self):
        pass

    def check_module(self, module, config):
        try:
            section = config.options(module)
        except:
            return True

        for option in section:
            if option not in ('enable', ):
                continue

            enable = config.get(module, option)
            if enable.lower() in ('false', ):
                return False

        return True

    def set_basedir(self, url):
        if self.baseDir:
            return

        t = datetime.datetime.now()
        m = hashlib.md5()
        m.update(url)

        base = os.getenv('THUG_LOGBASE', '..')
        self.baseDir = os.path.join(base, 'logs', m.hexdigest(), t.strftime("%Y%m%d%H%M%S"))

        try:
            os.makedirs(self.baseDir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise

        with open(os.path.join(base, 'logs', 'thug.csv'), 'a+r') as fd:
            csv_line = '%s,%s\n' % (m.hexdigest(), url, )
            for l in fd.readlines():
                if l == csv_line:
                    return

            fd.write(csv_line)

    def set_absbasedir(self, basedir):
        self.baseDir = basedir

        try:
            os.makedirs(self.baseDir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise
