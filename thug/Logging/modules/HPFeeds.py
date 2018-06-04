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

import os
import json
import struct
import socket
import hashlib
import logging
import six.moves.configparser as ConfigParser

log = logging.getLogger("Thug")


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
    formats = ('maec11', )

    OP_ERROR        = 0
    OP_INFO         = 1
    OP_AUTH         = 2
    OP_PUBLISH      = 3
    OP_SUBSCRIBE    = 4

    def __init__(self, thug_version):
        self.unpacker     = FeedUnpack()
        self.thug_version = thug_version
        self.opts         = dict()
        self.url          = ""
        self.enabled      = True

        self.__init_config()

    def __init_config(self):
        config = ConfigParser.ConfigParser()

        conf_file = os.path.join(log.configuration_path, 'logging.conf')

        if not os.path.exists(conf_file):
            conf_file = os.path.join(log.configuration_path, 'logging.conf.default')

        if not os.path.exists(conf_file):
            self.enabled = False
            return

        config.read(conf_file)

        for option in config.options('hpfeeds'):
            self.opts[option] = str(config.get('hpfeeds', option))

    def set_url(self, url):
        self.url = url

    def msg_hdr(self, op, data):
        return struct.pack('!iB', 5 + len(data), op) + data

    def msg_publish(self, chan, data):
        # if isinstance(data, str):
        #    data = data.encode('latin1')

        return self.msg_hdr(self.OP_PUBLISH,
                            struct.pack('!B', len(self.opts['ident'])) +
                            self.opts['ident'] +
                            struct.pack('!B', len(chan)) +
                            chan +
                            data)

    def msg_auth(self, rand):
        _hash = hashlib.sha1(rand + self.opts['secret']).digest()
        return self.msg_hdr(self.OP_AUTH,
                            struct.pack('!B', len(self.opts['ident'])) +
                            self.opts['ident'] +
                            _hash)

    def msg_send(self, msg):
        self.sockfd.send(msg)

    def get_data(self, host, port):
        self.sockfd.settimeout(3)

        try:
            self.sockfd.connect((host, port))
        except Exception:
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
                    name, rest = rest[1:1 + ord(rest[0])], buffer(rest, 1 + ord(rest[0]))  # pylint:disable=unused-variable
                    rand = str(rest)

                    self.msg_send(self.msg_auth(rand))
                    self.msg_send(self.msg_publish(chan, pubdata))
                    published = True
                    self.sockfd.settimeout(0.1)
                if opcode == self.OP_ERROR:
                    log.warning('[HPFeeds] Error message from server: %s', data)

            try:
                d = self.sockfd.recv(1024)
            except socket.timeout:
                break

    def __log_event(self, pubdata):
        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data = self.get_data(self.opts['host'], int(self.opts['port']))
        if data is None:
            return

        self.publish_data(data, 'thug.events', pubdata)
        self.sockfd.close()

    def log_event(self, basedir):
        if not self.enabled:
            return

        if log.ThugOpts.local:
            return

        m = None

        for module in self.formats:
            if module in log.ThugLogging.modules:
                p = log.ThugLogging.modules[module]
                m = getattr(p, 'get_%s_data' % (module, ), None)
                if m:
                    break

        if m is None:
            return

        data = m(basedir)
        self.__log_event(data)

    def log_file(self, pubdata, url = None, params = None):
        if not self.enabled:
            return

        if log.ThugOpts.local:
            return

        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data = self.get_data(self.opts['host'], int(self.opts['port']))
        if data is None:
            return

        self.publish_data(data, 'thug.files', json.dumps(pubdata))
        self.sockfd.close()

    def log_warning(self, pubdata):
        if not self.enabled:
            return

        if log.ThugOpts.local:
            return

        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data = self.get_data(self.opts['host'], int(self.opts['port']))
        if data is None:
            return

        self.publish_data(data, 'thug.warnings', json.dumps({'url': self.url, 'warning': pubdata}))
        self.sockfd.close()


if __name__ == '__main__':
    hpfeeds = HPFeeds('0.8.19')
    hpfeeds.log_event('Test foobar!')
