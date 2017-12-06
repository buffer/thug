#!/usr/bin/env python
#
# TestURLClassifier.py
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

import unittest
import yara
import json


class TestURLClassifier(unittest.TestCase):
    rule_file = "../rules/urlclassifier.yar"
    test_file = "testurlclassifier.json"

    def setUp(self):
        self.rules = yara.compile(self.rule_file)

    def test(self):
        with open(self.test_file) as fd:
            tests = json.load(fd)

        for t in tests['tests']:
            self.assertEqual(str(self.rules.match(data = t['url'])), t['output'])


if __name__ == '__main__':
    unittest.main()
