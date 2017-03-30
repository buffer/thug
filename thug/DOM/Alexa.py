#!/usr/bin/env python
#
# Alexa.py
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

import random

AlexaTopSites = [
        'http://www.google.com',
        'http://www.youtube.com',
        'http://www.facebook.com',
        'http://www.baidu.com',
        'http://www.wikipedia.org',
        'http://www.yahoo.com',
        'http://www.reddit.com',
        'http://www.taobao.com',
        'http://www.amazon.com',
        'http://www.tmall.com',
        'http://www.sohu.com',
        'http://www.twitter.com',
        'http://www.live.com',
        'http://www.instagram.com',
        'http://www.jd.com',
        'http://www.linkedin.com',
        'http://www.netflix.com',
        'http://www.t.co',
        'http://www.imgur.com',
        'http://www.ebay.com',
        'http://www.pornhub.com',
        'http://www.detail.tmall.com',
        'http://www.wordpress.com',
        'http://www.msn.com',
        'http://www.bing.com',
        'http://www.tumblr.com',
        'http://www.microsoft.com',
        'http://www.stackoverflow.com',
        'http://www.twitch.tv',
        'http://www.imdb.com',
        'http://www.blogspot.com',
        'http://www.office.com',
        'http://www.github.com',
        'http://www.microsoftonline.com',
        'http://www.apple.com',
        'http://www.popads.net',
        'http://www.diply.com',
        'http://www.pinterest.com',
        'http://www.csdn.net',
        'http://www.paypal.com',
        'http://www.adobe.com',
        'http://www.whatsapp.com',
        'http://www.xvideos.com',
        'http://www.xhamster.com',
        'http://www.pixnet.net',
        'http://www.login.tmall.com',
        'http://www.soso.com',
        'http://www.coccoc.com',
        'http://www.txxx.com',
        'http://www.dropbox.com',
        'http://www.googleusercontent.com',
        'http://www.bbc.co.uk',
]

random.shuffle(AlexaTopSites)
Alexa = AlexaTopSites[:random.randint(5, 9)]
