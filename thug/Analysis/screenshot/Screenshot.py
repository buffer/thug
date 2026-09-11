import logging

try:
    from playwright.sync_api import sync_playwright

    PLAYWRIGHT_MODULE = True
except ImportError:  # pragma: no cover
    PLAYWRIGHT_MODULE = False


log = logging.getLogger("Thug")


class Screenshot:
    content_types = ("text/html",)
    resource_types = ("image", "stylesheet")

    def __init__(self):
        self.enable = PLAYWRIGHT_MODULE

    def run(self, window, url, response, ctype):
        if not self.enable or not log.ThugOpts.screenshot:
            return

        if not ctype.startswith(self.content_types):
            return

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
