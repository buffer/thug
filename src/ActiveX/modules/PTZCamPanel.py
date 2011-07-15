# RTS Sentry Digital Surveillance PTZCamPanel Class (CamPanel.dll 2.1.0.2)
# CVE-NOMATCH

acct = ActiveXAcct[self]

def ConnectServer(server,user):
    global acct

    if len(user) > 1024:
        acct.add_alert('PTZCamPanel ConnectServer() overflow in user arg')

self.ConnectServer = ConnectServer
