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
import logging
import datetime

log = logging.getLogger("Thug")


class BaseLogging(object):
    def __init__(self):
        self.baseDir = None

    def check_module(self, module, config):
        if not getattr(log.ThugOpts, "%s_logging" % (module, ), True):
            return False

        try:
            section = config.options(module)
        except Exception:
            return True

        for option in section:
            if option not in ('enable', ): # pragma: no cover
                continue

            enable = config.getboolean(module, option)
            if not enable:
                return False

        return True # pragma: no cover

    def set_basedir(self, url):
        if self.baseDir:
            return

        t = datetime.datetime.now()
        m = hashlib.md5()
        m.update(url.encode('utf8'))

        base = os.getenv('THUG_LOGBASE', os.pardir if os.access(os.pardir, os.W_OK) else '/tmp/thug')
        self.baseDir = os.path.join(base, 'logs', m.hexdigest(), t.strftime("%Y%m%d%H%M%S"))

        if not log.ThugOpts.file_logging:
            return

        try:
            os.makedirs(self.baseDir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else: # pragma: no cover
                raise

        thug_csv = os.path.join(base, 'logs', 'thug.csv')
        csv_line = '{},{}\n'.format(m.hexdigest(), url)

        if os.path.exists(thug_csv):
            with open(thug_csv, 'r') as fd:
                for line in fd.readlines():
                    if line == csv_line:
                        return

        with open(thug_csv, 'at+') as fd:
            fd.write(csv_line)

    def set_absbasedir(self, basedir):
        self.baseDir = basedir

        if not log.ThugOpts.file_logging:
            return

        try:
            os.makedirs(self.baseDir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise
