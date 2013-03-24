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
# Modified by Angelo Dell'Aera: Designed the more generic Classifier 
# module and embedded this module into such module

import os
import re
import logging
import json
from BaseClassifier import BaseClassifier

log = logging.getLogger("Thug")

class URLClassifier(BaseClassifier):
    default_rule_file = "urlclassifier.json"

    def __init__(self, rules = [], verified_only = False):
        BaseClassifier.__init__(self)
        self.verified_only = verified_only

        for rule in rules:
            self.add_rule(rule)

    def add_rule(self, rule_file):
        if not os.path.exists(rule_file):
            log.warn("[URL Classifier] Skipping not existing classification rule file %s" % (rule_file, ))
            return

        with open(rule_file, "rt") as fh:
            rules = json.load(fh)

            for rule in rules["rules"]:
                rule["compiled"] = re.compile(rule["regex"], re.IGNORECASE)
                self.rules.append(rule)

    def classify(self, url):
        for rule in self.rules:
            if self.verified_only and not rule["verified"]:
                continue

            if rule["compiled"].search(url):
                self.matches.append((url, rule))
                log.ThugLogging.add_behavior_warn("[URL Classifier] URL: %s Exploit kit: %s (rule: %s)" % (url, 
                                                                                                           rule["kit"],
                                                                                                           rule["name"], ))

    def print_classification(self):
        if not self.matches:
            return

        for match in self.matches:
            url  = match[0]
            rule = match[1]
            log.warn("[URL Classifier] URL: %s Exploit kit: %s (rule: %s)" % (url, 
                                                                              rule["kit"], 
                                                                              rule["name"], ))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description = "Classifies a given URL")
    parser.add_argument('url', 
                        help    = "The URL to classify")
    
    parser.add_argument("--rules", 
                        help    = "Additional rule files (default: urlclassifier.json", 
                        nargs   = "+", 
                        default = [])

    parser.add_argument("--verified", 
                        help    = "Only report verified data", 
                        action  = "store_true", 
                        default = False)

    args = parser.parse_args()

    classifier = URLClassifier(args.rules, args.verified)
    classifier.classify(args.url)
    classifier.print_classification()
