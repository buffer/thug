import io
import logging
import bs4

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_MODULE = True
except ImportError:  # pragma: no cover
    PLAYWRIGHT_MODULE = False


try:
    import weasyprint
    WEASYPRINT_MODULE = True
except ImportError:  # pragma: no cover
    WEASYPRINT_MODULE = False

log = logging.getLogger("Thug")


class OldScreenshot:
    content_types = ("text/html",)

    def __init__(self):
        self.enable = WEASYPRINT_MODULE

    def run(self, window, url, response, ctype):
        if not self.enable or not log.ThugOpts.screenshot:
            return

        if not ctype.startswith(self.content_types):
            return  # pragma: no cover

        soup = bs4.BeautifulSoup(response.content, "html5lib")

        for img in soup.find_all("img"):
            src = img.get("src", None)
            if not src:
                continue  # pragma: no cover

            norm_src = log.HTTPSession.normalize_url(window, src)
            if norm_src:
                img["src"] = norm_src

        content = soup.prettify(formatter=None)

        try:
            html = weasyprint.HTML(string=content)
            document = html.render()

            with io.BytesIO() as screenshot:
                document.write_pdf(screenshot)
                screenshot.seek(0)
                log.ThugLogging.log_screenshot(url, screenshot.read())
        except Exception as e:  # pragma: no cover,pylint:disable=broad-except
            log.warning("[SCREENSHOT] Error: %s", str(e))


class Screenshot:
    content_types = ("text/html",)
    resource_types = ("image", "stylesheet")

    def __init__(self):
        self.enable = PLAYWRIGHT_MODULE

    def run(self, window, url, response, ctype):
        if not self.enable or not log.ThugOpts.screenshot:
            return

        if not ctype.startswith(self.content_types):
            return  # pragma: no cover

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            def block_resource_type(route):
                if route.request.resource_type in self.resource_types:
                    route.continue_()
                else:
                    route.abort()

            page.route("**/*", block_resource_type)

            try:
                page.set_content(response.text)
                screenshot = page.screenshot(type="png", full_page=True)
                browser.close()
                log.ThugLogging.log_screenshot(url, screenshot)
            except Exception as e:
                log.warning("[SCREENSHOT] Error: %s", str(e))
