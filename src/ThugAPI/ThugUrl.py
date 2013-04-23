#!/usr/bin/env python
#
# ThugUrl.py
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
import urlparse
import urllib

log = logging.getLogger("Thug")

def fixUrl(url):
    # turn url string into unicode
    if not isinstance(url,unicode):
        url = url.decode('utf8')

    # parse it
    parsed = urlparse.urlsplit(url)

    # divide the netloc further
    userpass,at,hostport = parsed.netloc.rpartition('@')
    user,colon1,pass_ = userpass.partition(':')
    host,colon2,port = hostport.partition(':')

    # encode each component
    scheme = parsed.scheme.encode('utf8')
    user = urllib.quote(user.encode('utf8'))
    colon1 = colon1.encode('utf8')
    pass_ = urllib.quote(pass_.encode('utf8'))
    at = at.encode('utf8')
    host = host.encode('idna')
    colon2 = colon2.encode('utf8')
    port = port.encode('utf8')
    path = '/'.join(  # could be encoded slashes!
        urllib.quote(urllib.unquote(pce).encode('utf8'),'')
        for pce in parsed.path.split('/')
    )
    query = urllib.quote(urllib.unquote(parsed.query).encode('utf8'),'=&?/')
    fragment = urllib.quote(urllib.unquote(parsed.fragment).encode('utf8'))

    # put it back together
    netloc = ''.join((user,colon1,pass_,at,host,colon2,port))
    return urlparse.urlunsplit((scheme,netloc,path,query,fragment))


class ThugUrl(str):
    def __new__(self, url):
        return str.__new__(self, fixUrl(url))
