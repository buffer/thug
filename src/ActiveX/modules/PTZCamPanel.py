# RTS Sentry Digital Surveillance PTZCamPanel Class (CamPanel.dll 2.1.0.2)
# CVE-NOMATCH

def ConnectServer(server,user):
	if len(user)>1024:
		add_alert('PTZCamPanel ConnectServer() overflow in user arg')

self.ConnectServer=ConnectServer
