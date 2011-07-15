
acct = ActiveXAcct[self]

def ShockwaveVersion(arg):
    global acct

    if len(arg) >= 768 * 768:
        acct.add_alert('Adobe Shockwave ShockwaveVersion() Stack Overflow')

self.ShockwaveVersion = ShockwaveVersion
