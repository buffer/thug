#!/usr/bin/env python
#
# hpfeeds.py
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
import struct
import socket
import hashlib
import logging
from time import sleep

logger = logging.getLogger('pyhpfeeds')

OP_ERROR	    = 0
OP_INFO		    = 1
OP_AUTH		    = 2
OP_PUBLISH	    = 3
OP_SUBSCRIBE	= 4
BUFSIZ          = 16384

__all__ = ["new", "FeedException"]

def msghdr(op, data):
	return struct.pack('!iB', 5+len(data), op) + data

def msgpublish(ident, chan, data):
#	if isinstance(data, str):
#		data = data.encode('latin1')
	return msghdr(OP_PUBLISH, struct.pack('!B', len(ident)) + ident + struct.pack('!B', len(chan)) + chan + data)

def msgsubscribe(ident, chan):
	return msghdr(OP_SUBSCRIBE, struct.pack('!B', len(ident)) + ident + chan)

def msgauth(rand, ident, secret):
	_hash = hashlib.sha1(rand+secret).digest()
	return msghdr(OP_AUTH, struct.pack('!B', len(ident)) + ident + _hash)

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
			raise StopIteration('No message.')

		ml, opcode = struct.unpack('!iB', buffer(self.buf,0,5))
		if len(self.buf) < ml:
			raise StopIteration('No message.')
		
		data = bytearray(buffer(self.buf, 5, ml-5))
		del self.buf[:ml]
		return opcode, data

class FeedException(Exception):
	pass

class HPC(object):
	def __init__(self, host, port, ident, secret, timeout=3, reconnect=False, sleepwait=20):
		self.host, self.port = host, port
		self.ident, self.secret = ident, secret
		self.timeout = timeout
		self.reconnect = reconnect
		self.sleepwait = sleepwait
		self.brokername = 'unknown'
		self.connected = False
		self.stopped = False
		self.unpacker = FeedUnpack()

		self.connect()

	def connect(self):
		logger.info('connecting to %s:%s', self.host, self.port)
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.settimeout(self.timeout)
		try: self.s.connect((self.host, self.port))
		except: raise FeedException('Could not connect to broker.')
		self.connected = True
		
		try: d = self.s.recv(BUFSIZ)
		except socket.timeout: raise FeedException('Connection receive timeout.')
		
		self.unpacker.feed(d)
		for opcode, data in self.unpacker:
			if opcode == OP_INFO:
				rest = buffer(data, 0)
				name, rest = rest[1:1+ord(rest[0])], buffer(rest, 1+ord(rest[0]))
				rand = str(rest)

				logger.debug('info message name: %s, rand: %s', name, repr(rand))
				self.brokername = name
				
				self.s.send(msgauth(rand, self.ident, self.secret))
				break
			else:
				raise FeedException('Expected info message at this point.')

			self.s.settimeout(None)
			self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

			if sys.platform in ('linux2', ):
				self.s.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 60)

	def _run(self, message_callback, error_callback):
		while not self.stopped:
			while self.connected:
				d = self.s.recv(BUFSIZ)
				if not d:
					self.connected = False
					break

				self.unpacker.feed(d)
				for opcode, data in self.unpacker:
					if opcode == OP_PUBLISH:
						rest = buffer(data, 0)
						ident, rest = rest[1:1+ord(rest[0])], buffer(rest, 1+ord(rest[0]))
						chan, content = rest[1:1+ord(rest[0])], buffer(rest, 1+ord(rest[0]))

						message_callback(str(ident), str(chan), content)
					elif opcode == OP_ERROR:
						error_callback(data)

				if self.stopped: break

			if self.stopped: break
			self.connect()

	def run(self, message_callback, error_callback):
		if not self.reconnect:
			self._run(message_callback, error_callback)
		else:
			while True:
				self._run(message_callback, error_callback)
				# reconnect now we've failed
				sleep(self.sleepwait)
				while True:
					try:
						self.connect()
						break
					except FeedException:
						sleep(self.sleepwait)

	def subscribe(self, chaninfo):
		if type(chaninfo) == str:
			chaninfo = [chaninfo,]
		for c in chaninfo:
			self.s.send(msgsubscribe(self.ident, c))
	def publish(self, chaninfo, data):
		if type(chaninfo) == str:
			chaninfo = [chaninfo,]
		for c in chaninfo:
			self.s.send(msgpublish(self.ident, c, data))

	def stop(self):
		self.stopped = True

	def close(self):
		try: self.s.close()
		except: logger.warn('Socket exception when closing.')

def new(host=None, port=10000, ident=None, secret=None, reconnect=True, sleepwait=20):
	return HPC(host, port, ident, secret, reconnect)

