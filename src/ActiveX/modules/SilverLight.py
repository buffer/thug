import logging
log = logging.getLogger("Thug")

def isVersionSupported(self, version):
    shockwave = log.ThugVulnModules.shockwave_flash.split('.')
    sversion  = version.split('?')

    if len(sversion) == 1:
        sversion = version.split('.')

    if len(sversion) != 4:
        return False
   
    for i in range(0, 4):
        if int(sversion[i]) > int(shockwave[i]):
            return False

    return True
