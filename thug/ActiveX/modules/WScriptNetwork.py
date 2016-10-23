import logging
log = logging.getLogger("Thug")

class WshCollection(list):
    def __getattr__(self, name):
        if name.lower() == 'length':
            return len(self)

    def Item(self, pos):
        return self[pos]

def EnumPrinterConnections(self):
    log.ThugLogging.add_behavior_warn("[WScript.Network ActiveX] Got request to PrinterConnections")
    return WshCollection(['LPT1', '\\\\S2811KIV099\\DR099120', 'LPT2', '\\\\S2811KIV099\\DR099120'])

def EnumNetworkDrives(self):
    log.ThugLogging.add_behavior_warn("[WScript.Network ActiveX] Got request to EnumNetworkDrives")
    return WshCollection(['M:', '\\\\nas\\Public'])
