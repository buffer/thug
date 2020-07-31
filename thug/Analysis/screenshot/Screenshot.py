import sys
import logging
import bs4

try:
    import imgkit
    IMGKIT_MODULE = True
except ImportError: # pragma: no cover
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

        soup = bs4.BeautifulSoup(response.content, "html5lib")

        for img in soup.find_all('img'):
            src = img.get('src', None)
            if not src:
                continue # pragma: no cover

            norm_src = log.HTTPSession.normalize_url(window, src)
            if norm_src:
                img['src'] = norm_src

        content = soup.prettify(formatter = None)
        options = {
            'quiet' : ''
        }

        if sys.platform in ('linux', ):
            options['xvfb'] = ''

        try:
            screenshot = imgkit.from_string(content, False, options = options)
            log.ThugLogging.log_screenshot(url, screenshot)
        except Exception as e: # pragma: no cover
            log.warning("[SCREENSHOT] Error: %s", str(e))
