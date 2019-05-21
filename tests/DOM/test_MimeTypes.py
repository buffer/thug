import os
import logging

import thug

from thug.ThugAPI.ThugVulnModules import ThugVulnModules
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.DOM.MimeTypes import MimeTypes

log = logging.getLogger("Thug")

configuration_path = thug.__configuration_path__
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugVulnModules = ThugVulnModules()
log.ThugOpts = ThugOpts()


class TestMimeTypes(object):
    def test_items(self):
        mimetypes = MimeTypes()

        assert mimetypes[100]['description'] is None
        assert mimetypes['application/x-ms-wmz']['description'] in ('Windows Media Player', )
        assert mimetypes.namedItem('application/x-ms-wmz')['description'] in ('Windows Media Player', )
