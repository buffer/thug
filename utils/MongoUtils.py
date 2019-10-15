#!/usr/bin/env python
#
# MongoUtils.py
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

import sys
import getopt

MONGO_MODULE = True

try:
    import gridfs
    import pymongo
    from bson.objectid import ObjectId
except ImportError:
    MONGO_MODULE = False


class MongoUtils(object):
    def __init__(self, host = "localhost", port = 27017):
        self.__check_mongo_module()
        self.__init_db(host, port)

    def __check_mongo_module(self):
        if not MONGO_MODULE:
            print('[MongoUtils] PyMongo not installed. Please install it and retry.')
            sys.exit(0)

    def __init_db(self, host, port):
        # MongoDB Connection class is marked as deprecated (MongoDB >= 2.4).
        # The following code tries to use the new MongoClient if available and
        # reverts to the old Connection class if not. This code will hopefully
        # disappear in the next future.
        client = getattr(pymongo, 'MongoClient', None)
        if client is None:
            client = getattr(pymongo, 'Connection', None)

        try:
            connection = client(host, int(port))
        except Exception:
            print('[MongoUtils] MongoDB instance not available')
            sys.exit(0)

        db                = connection.thug
        dbfs              = connection.thugfs
        self.urls         = db.urls
        self.analyses     = db.analyses
        self.thugfs       = gridfs.GridFS(dbfs)

        self.collections  = (db.urls,
                             db.analyses,
                             db.locations,
                             db.connections,
                             db.graphs,
                             db.samples,
                             db.behaviors,
                             db.certificates,
                             db.virustotal,
                             db.honeyagent,
                             db.exploits,
                             db.codes,
                             db.json)

    def list_analyses(self):
        print("ID\t\t\t\t| URL\t\t\t\t| Analysis datetime\n")

        for analysis in self.analyses.find():
            urls = self.urls.find(_id = analysis['url_id'])
            if not urls:
                continue

            url = urls[0]['url']
            print("%s\t| %s\t| %s" % (analysis['_id'], 
                                      url,
                                      analysis['timestamp']))

    def remove_analysis(self, analysis):
        analysis_id = analysis['_id']
        for collection in self.collections:
            collection.remove({"_id": analysis_id})

        self.thugfs.delete({"_id": analysis_id})

    def query_analysis_by_id(self, analysis_id):
        analysis = self.analyses.find_one({'_id': ObjectId(analysis_id)})
        if not analysis:
            print("[MongoUtils] Analysis ID not found")
            return None

        return analysis


def usage():
    msg = """
Synopsis:
    MongoUtils.py

    Usage:
        python MongoUtils.py [ options ]

    Options:
        -h, --help              \tDisplay this help information
        -l, --ls                \tList all the analyses
        -r, --rm=               \tRemove the analysis identified by the specified ID
        -M, --mongodb-address=  \tSpecify address and port of the MongoDB instance (format: host:port)
"""
    print(msg)
    sys.exit(0)

def main(args):
    host = 'localhost'
    port = 27017

    try:
        options, args = getopt.getopt(args, 'hlr:M:', 
                                      ['help',
                                       'ls',
                                       'rm=',
                                       'mongodb-address='])
    except getopt.GetoptError:
        usage()

    if not options and not args:
        usage()

    for option in options:
        if option[0] in ('-h', '--help'):
            usage()
        elif option[0] in ('-M', '--mongodb-address'):
            host, port = option[1].split(":")

    mongoutils = MongoUtils(host, port)

    for option in options:
        if option[0] in ('-l', '--ls'):
            mongoutils.list_analyses()
            
    for option in options:
        if option[0] in ('-r', '--rm'):
            analysis = mongoutils.query_analysis_by_id(option[1])
            if analysis:
                mongoutils.remove_analysis(analysis)

if __name__ == '__main__':
    main(sys.argv[1:])
