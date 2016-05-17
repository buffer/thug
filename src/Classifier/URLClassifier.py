#!/usr/bin/env python
#
# URLClassifier.py
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
#
# Original code written by Thorsten Sick <thorsten.sick@avira.com> 
# from Avira (developed for the iTES Project http://ites-project.org)
#
# Modified by Angelo Dell'Aera:
#   - Designed the more generic Classifier module and embedded this
#     module into such module
#   - Converted to YARA rules

import logging
from .BaseClassifier import BaseClassifier

log = logging.getLogger("Thug")

class URLClassifier(BaseClassifier):
    default_rule_file = "rules/urlclassifier.yar"
    classifier        = "URL Classifier"

    def __init__(self):
        BaseClassifier.__init__(self)

    def classify(self, url):
        for match in self.rules.match(data = url):
            self.matches.append((url, match))

            rule = " ".join(match.rule.split('_'))
            tags = ", ".join([" ".join(t.split('_')) for t in match.tags])
            log.ThugLogging.add_behavior_warn("[URL Classifier] URL: %s (Rule: %s, Classification: %s)" % (url, rule, tags, ))
