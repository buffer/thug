
class System:
    def __init__(self):
        pass

    def getProperty(self, property):
        if property == "java.version":
            return '1.6.1_15'

        if property == "java.vendor":
            return 'Sun Microsystems Inc.'

