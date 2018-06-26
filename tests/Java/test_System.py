import logging

from thug.Java.System import System
from thug.ThugAPI.ThugVulnModules import ThugVulnModules

log = logging.getLogger("Thug")
log.ThugVulnModules = ThugVulnModules()


class TestSystem:
    system = System()

    def test_version(self):
        version = self.system.getProperty("java.version")
        assert version in ('1.6.0_32', )

    def test_vendor(self):
        vendor = self.system.getProperty("java.vendor")
        assert vendor in ('Sun Microsystems Inc.', )
