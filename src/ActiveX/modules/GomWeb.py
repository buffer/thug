# GOM Player GOM Manager ActiveX Control
# CVE-2007-5779

def OpenURL(arg):
    if len(arg) > 500:
        add_alert('GOM Player 2 overflow in OpenURL()')

self.OpenURL = OpenURL
