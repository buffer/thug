#!/usr/bin/env python
#
# BaseClassifier.py
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
import re
import json
from abstractmethod import abstractmethod

class BaseClassifier:
    def __init__(self):
        self.rules   = list()
        self.matches = list()
        self.__init_rules()

    def __init_rules(self):
        p = getattr(self, 'default_rule_file', None)
        if p is None:
            return

        rules = os.path.join(os.path.dirname(os.path.abspath(__file__)), p)
        self.add_rule(rules)

    @abstractmethod
    def add_rule(self, rule_file):
        pass 

    def add_rule_file(self, rule_file):
        self.add_rule(rule_file)

    @abstractmethod
    def classify(self):
        pass

    @property
    def result(self):
        return self.matches
