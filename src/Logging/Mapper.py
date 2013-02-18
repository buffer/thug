#!/usr/bin/env python
#
# Mapper.py
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
# Provided by Thorsten Sick <thorsten.sick@avira.com> from Avira
# For the iTES Project http://ites-project.org

import os
from subprocess import call
import json
import fnmatch
try:
    import urlib.parse as urlparse
except ImportError:
    import urlparse


class DictDiffer(object):
    """
    Calculate the difference between two dictionaries as:
    (1) items added
    (2) items removed
    (3) keys same in both but changed values
    (4) keys same in both and unchanged values
    """
    def __init__(self, current_dict, past_dict):
        self.current_dict, self.past_dict = current_dict, past_dict
        self.set_current, self.set_past =\
            set(current_dict.keys()), set(past_dict.keys())
        self.intersect = self.set_current.intersection(self.set_past)

    def added(self):
        return self.set_current - self.intersect

    def removed(self):
        return self.set_past - self.intersect

    def changed(self):
        return set(o for o in self.intersect if self.past_dict[o] !=\
            self.current_dict[o])

    def unchanged(self):
        return set(o for o in self.intersect if self.past_dict[o] ==\
            self.current_dict[o])

    def anychange(self):
        if len(self.added()):
            return True
        if len(self.removed()):
            return True
        if len(self.changed()):
            return True
        return False


class Mapper():
    """ Map URL relationships
    """

    def __init__(self, resdir, simplify=False):
        """

        @resdir: Directory to store the result svg in
        @simplify: Reduce the urls to server names
        """
        self.resdir = resdir
        self.simplify = simplify
        self.dotfile = os.path.join(self.resdir, "avdot.dot")
        self.dfh = None
        self._write_start()
        self.data = {"locations": [], "connections": []}

    def _write_start(self):
        """ Write the dot header
        """
        self.dfh = open(self.dotfile, "w")
        self.dfh.write('digraph {\nrankdir="LR";\ngraph[fontsize=10]\n')

    def _write_stop(self):
        """ Write the dot footer
        """

        if self.dfh:
            self._dot_from_data()
            self.dfh.write("}")
            self.dfh.close()
            self.dfh = None

    def _dot_from_data(self):
        # Create dot from data
        if "locations" in self.data:
            for loc in self.data["locations"]:
                shape = None
                fillcolor = None
                # Markup
                for a in ["text/html", "text/xml", "text/css"]:
                    if (loc["content-type"] and
                        loc["content-type"].lower().startswith(a)):
                        shape = "box"
                # Images
                for a in ["image/"]:
                    if (loc["content-type"] and
                        loc["content-type"].lower().startswith(a)):
                        shape = "oval"
                # Executable stuff
                for a in ["application/javascript",
                          "text/javascript",
                          "application/x-javascript"]:
                    if (loc["content-type"] and
                        loc["content-type"].lower().startswith(a)):
                        shape = "hexagon"

                if "error" in loc["flags"]:
                    fillcolor = "orange"

                self.dfh.write('"%s" [label="%s"' % (loc["url"], loc["url"]))
                if shape:
                    self.dfh.write("shape = %s," % shape)
                if fillcolor:
                    self.dfh.write("style = filled, fillcolor = %s,"\
                        % fillcolor)
                self.dfh.write("]\n")

        if "connections" in self.data:
            # Add edges
            for con in self.data["connections"]:
                color = None
                if "method" in ["iframe"]:
                    color = "orange"

                self.dfh.write('"%s" -> "%s" [label="%s",' %\
                    (con["source"], con["destination"], con["method"]))
                if color:
                    self.dfh.write("color = %s," % color)
                self.dfh.write("]\n")

    def _add_to_loc(self, loc):
        """ Add location information to location data
        """
        if self.simplify:
            url = urlparse.urlparse(loc["url"]).netloc
            if url:
                loc["url"] = url

        for a in self.data["locations"]:
            d = DictDiffer(a, loc)
            if not d.anychange():
                return
        self.data["locations"].append(loc)

    def _add_to_con(self, con):
        """ Add connection information to connection data
        """
        if self.simplify:
            url = urlparse.urlparse(con["source"]).netloc
            if url:
                con["source"] = url
            url = urlparse.urlparse(con["destination"]).netloc
            if url:
                con["destination"] = url

        for a in self.data["connections"]:
            d = DictDiffer(a, con)
            if not d.anychange():
                return
        self.data["connections"].append(con)

    def add_data(self, data):
        # Add nodes
        if "locations" in data:
            for loc in data["locations"]:
                self._add_to_loc(loc)

        if "connections" in data:
            for con in data["connections"]:
                self._add_to_con(con)

    def add_file(self, filename):
        """ Add data file
        """
        try:
            self.add_data(json.load(open(filename, "r")))
        except ValueError:
            pass

    def write_svg(self):
        """ Create SVG out of the dotfile

        @dotfile: In-dotfile
        """

        self._write_stop()
        svgfile = os.path.join(self.resdir, "map.svg")
        cmd = ["dot", "-Tsvg", self.dotfile, "-o", svgfile]
        res = call(cmd)


def allFiles(root, patterns="*", single_level=False, yield_folders=False):
    """ Walk files
    """

    patterns = patterns.split(";")
    for path, subdirs, files in os.walk(root):
        if yield_folders:
            files.extend(subdirs)
        files.sort()
        for name in files:
            for pattern in patterns:
                if fnmatch.fnmatch(name, pattern):
                    yield os.path.join(path, name)
                    break
        if single_level:
            break

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Receives jobs and starts Thug to process them')
    parser.add_argument('--resdir', help='Result dir', default=".")
    parser.add_argument('--source', help='Source file or dir',
        default="avlog.json")
    parser.add_argument('--simplify', help='Reduce the URLs to servernames',
        default=False, action="store_true")

    args = parser.parse_args()
    m = Mapper(args.resdir, simplify=args.simplify)
    if os.path.isdir(args.source):
        for afile in allFiles(args.source, "avlog.json"):
            print afile
            m.add_file(afile)
    else:
        m.add_file(args.source)
    m.write_svg()
