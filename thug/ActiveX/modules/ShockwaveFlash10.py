
import logging

log = logging.getLogger("Thug")


def GetVariable(self, arg):
    if arg in ("$version", ):
        version = ['0', '0', '0', '0']
        idx     = 0

        for p in log.ThugVulnModules.shockwave_flash.split('.'):
            version[idx] = p
            idx += 1

        return "WIN %s" % (','.join(version))

    return "" # pragma: no cover
