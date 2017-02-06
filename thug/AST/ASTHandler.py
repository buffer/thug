#!/usr/bin/env python
#
# ASTHandler.py
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


class ASTHandler(object):
    def __init__(self):
        self.args = {
            'eval' : list(),
        }

    def handle_eval(self, args):
        for arg in args:
            s = str(arg)

            if s in self.args['eval']:
                continue

            if len(s) > 64:
                log.warning("[AST]: Eval argument length > 64")

            self.args['eval'].append(s)
