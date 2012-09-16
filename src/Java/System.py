
import logging
log = logging.getLogger("Thug")

class System:
    def __init__(self):
        pass

    def getProperty(self, property):
        if property == "java.version":
            javaplugin = log.ThugVulnModules._javaplugin.split('.')
            last       = javaplugin.pop()
            return '%s_%s' % ('.'.join(javaplugin), last)

        if property == "java.vendor":
            return 'Sun Microsystems Inc.'

