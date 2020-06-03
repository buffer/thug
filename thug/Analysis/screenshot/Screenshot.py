import os
import tempfile
import logging

import bs4

try:
    import imgkit
    IMGKIT_MODULE = True
except ImportError:
    IMGKIT_MODULE = False

log = logging.getLogger("Thug")


class Screenshot(object):
    content_types = ('text/html', )

    def __init__(self):
        self.enable = IMGKIT_MODULE

    def run(self, window, url, response, ctype):
        if not self.enable or not log.ThugOpts.screenshot:
            return

        if not ctype.startswith(self.content_types):
            return

        soup = bs4.BeautifulSoup(response.text, "lxml")

        for img in soup.find_all('img'):
            src = img.get('src', None)
            if not src:
                continue

            norm_src = log.HTTPSession.normalize_url(window, src)
            if norm_src:
                img['src'] = norm_src

        fd, path = tempfile.mkstemp(suffix = '.jpg')
        imgkit.from_string(str(soup), path)
        log.ThugLogging.log_screenshot(url, path)

        os.remove(path)
