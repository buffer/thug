#!/usr/bin/env python
#
# HPFeeds.py
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
import os
import struct
import socket
import base64
import hashlib
import logging
import json
import zipfile
import pefile
import ConfigParser

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

log = logging.getLogger("Thug.Logging")

class FeedUnpack(object):
	def __init__(self):
		self.buf = bytearray()

	def __iter__(self):
		return self

	def next(self):
		return self.unpack()

	def feed(self, data):
		self.buf.extend(data)

	def unpack(self):
		if len(self.buf) < 5:
			raise StopIteration('No message')

		ml, opcode = struct.unpack('!iB', buffer(self.buf, 0, 5))
		if len(self.buf) < ml:
			raise StopIteration('No message')
		
		data = bytearray(buffer(self.buf, 5, ml - 5))
		del self.buf[:ml]
		return opcode, data


class HPFeeds(object):
    OP_ERROR        = 0 
    OP_INFO         = 1 
    OP_AUTH         = 2 
    OP_PUBLISH      = 3 
    OP_SUBSCRIBE    = 4

    def __init__(self):
        self.unpacker = FeedUnpack()
        self.opts     = dict()
        self.__init_config()

    def __init_config(self):
        config = ConfigParser.ConfigParser()

        thug_base = os.getcwd().split("thug")[0]
        conf_file = "%sthug/src/Logging/logging.conf" % (thug_base, )
        config.read(conf_file)
        
        for option in config.options('HPFeeds'):
            self.opts[option] = config.get('HPFeeds', option)

    def msg_hdr(self, op, data):
        return struct.pack('!iB', 5 + len(data), op) + data

    def msg_publish(self, chan, data):
        if isinstance(data, str):
            data = data.encode('latin1')

        return self.msg_hdr(self.OP_PUBLISH, 
                            struct.pack('!B', len(self.opts['ident']))      + 
                                              self.opts['ident']            + 
                                              struct.pack('!B', len(chan))  + 
                                              chan                          + 
                                              data)

    def msg_auth(self, rand):
        hash = hashlib.sha1(rand + self.opts['secret']).digest()
        return self.msg_hdr(self.OP_AUTH, 
                           struct.pack('!B', len(self.opts['ident']))   + 
                                             self.opts['ident']         + 
                                             hash)
    

    def msg_send(self, msg):
        self.sockfd.send(msg)

    def get_data(self, host, port):
        self.sockfd.settimeout(3)

        try:
            self.sockfd.connect((host, port))
        except:
            log.warning('[HPFeeds] Unable to connect to broker')
            return None

        try:
            d = self.sockfd.recv(1024)
        except socket.timeout:
            log.warning('[HPFeeds] Timeout on banner')
            return None

        self.sockfd.settimeout(None)
        return d
            
    def publish_data(self, d, chan, pubdata):
        published = False

        while d and not published:
            self.unpacker.feed(d)

            for opcode, data in self.unpacker:
                if opcode == self.OP_INFO:
                    rest = buffer(data, 0)
                    name, rest = rest[1:1 + ord(rest[0])], buffer(rest, 1 + ord(rest[0]))
                    rand = str(rest)

                    self.msg_send(self.msg_auth(rand))
                    self.msg_send(self.msg_publish(chan, pubdata))
                    published = True
                    self.sockfd.settimeout(0.1)
                if opcode == self.OP_ERROR:
                    log.warning('[HPFeeds] Error message from server: {0}'.format(data))

            try:
                d = self.sockfd.recv(1024)
            except socket.timeout:
                break

    def log_event(self, pubdata):
        if not self.opts['enable']:
            return

        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        data = self.get_data(self.opts['host'], int(self.opts['port']))
        if data is None:
            return

        self.publish_data(data, 'thug.events', pubdata)
        self.sockfd.close()

    def is_pe(self, pubdata):
        try:
            pe = pefile.PE(data = pubdata, fast_load = True)
        except:
            return False

        return True

    def is_pdf(self, pubdata):
        return pubdata.startswith('%PDF')

    def is_jar(self, pubdata):
        try:
            z = zipfile.ZipFile(StringIO.StringIO(pubdata))
            if [t for t in z.namelist() if t.endswith('.class')]:
                return True
        except:
            pass

        return False

    def log_file(self, pubdata):
        if not self.opts['enable']:
            return

        if not pubdata:
            return

        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        data = self.get_data(self.opts['host'], int(self.opts['port']))
        if data is None:
            return

        p = dict()
        p['type'] = None

        if self.is_pe(pubdata):
            p['type'] = 'PE'

        if p['type'] is None and self.is_pdf(pubdata):
            p['type'] = 'PDF'

        if p['type'] is None and self.is_jar(pubdata):
            p['type'] = 'JAR'

        if p['type'] is not None:
            p['md5']  = hashlib.md5(pubdata).hexdigest()
            p['sha1'] = hashlib.sha1(pubdata).hexdigest()
            p['data'] = base64.b64encode(pubdata)

            self.publish_data(data, 'thug.files', json.dumps(p))
        
        self.sockfd.close()

if __name__ == '__main__':
    hpfeeds = HPFeeds()
    hpfeeds.log_event('thug', 'Test')

