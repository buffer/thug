#!/usr/bin/env python
#
# AsyncPrefetcher.py
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

from requests_futures.sessions import FuturesSession

log = logging.getLogger("Thug")


class AsyncPrefetcher:
    def __init__(self, window=None):
        self.session = FuturesSession()
        self.window = window
        self.responses = {}

    def build_http_headers(self, window):
        http_headers = {
            "Cache-Control": "no-cache",
            "Accept-Language": "en-US",
            "Accept": "*/*",
            "User-Agent": log.ThugOpts.useragent,
        }

        if window and window.url not in ("about:blank",):
            referer = (
                window.url if window.url.startswith("http") else f"http://{window.url}"
            )
            http_headers["Referer"] = referer

        return http_headers

    def _fetch(self, url, method):
        log.warning("[PREFETCHING] URL: %s", url)

        fetcher = getattr(self.session, method.lower())
        self.responses[url] = fetcher(
            url,
            headers=self.build_http_headers(self.window),
            timeout=log.ThugOpts.connect_timeout,
            verify=log.ThugOpts.ssl_verify,
            stream=True,
        )

    def fetch(self, url, method="GET"):
        if log.HTTPSession.no_fetch:
            return  # pragma: no cover

        if method.lower() not in (
            "get",
            "post",
        ):
            return  # pragma: no cover

        _url = log.HTTPSession.normalize_url(self.window, url)
        if _url is None:
            return  # pragma: no cover

        self._fetch(_url, method)
