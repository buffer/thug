# DivX Player 6.6.0 ActiveX Control
# CVE-NOMATCHd

def SetPassword(arg0):
	if len(arg0) > 128:
		add_alert('DivX overflow in SetPassword()');

self.SetPassword = SetPassword
