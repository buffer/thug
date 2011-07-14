
acct = ActiveXAcct[self]

def LaunchGui(arg0, arg1, arg2):
    global acct

    if len(arg0) > 1500:
        acct.add_alert('EnjoySAP.LaunchGUI overflow in arg0')

def PrepareToPostHTML(arg):
    global acct

    if len(arg) > 1000:
        acct.add_alert('EnjoySAP.PrepareToPostHTML overflow in arg0')

self.LaunchGui         = LaunchGui
self.PrepareToPostHTML = PrepareToPostHTML
