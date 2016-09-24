#!/usr/bin/env python
#
# Window.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import os
import sched
import time
import logging
import PyV8
import traceback
import urllib
import bs4 as BeautifulSoup
import jsbeautifier
import six
from .W3C import w3c
from .W3C.HTML.HTMLCollection import HTMLCollection
from .JSClass import JSClass
from .Navigator import Navigator
from .Location import Location
from .Screen import Screen
from .History import History
from .ClipboardData import ClipboardData
from .External import External
from .Sidebar import Sidebar
from .Chrome import Chrome
from .Opera import Opera
from .Console import Console
from .Components import Components
from .Crypto import Crypto
from .CCInterpreter import CCInterpreter
from .LocalStorage import LocalStorage
from .SessionStorage import SessionStorage
from thug.ActiveX.ActiveX import _ActiveXObject
from thug.AST.AST import AST
from thug.Debugger import Shellcode
from thug.Java.java import java

sched = sched.scheduler(time.time, time.sleep)
log = logging.getLogger("Thug")

import thug

class Window(JSClass):

    class Timer(object):
        def __init__(self, window, code, delay, repeat, lang = 'JavaScript'):
            self.window  = window
            self.code    = code
            self.delay   = float(delay) / 1000
            self.repeat  = repeat
            self.lang    = lang
            self.running = True

        def start(self):
            self.event = sched.enter(self.delay, 1, self.execute, ())
            try:
                sched.run()
            except: #pylint:disable=bare-except
                pass

        def stop(self):
            self.running = False
            if self.event in sched.queue:
                sched.cancel(self.event)

        def execute(self):
            if not self.running:
                return

            log.debug(str(self.code))

            with self.window.context as ctx:
                if isinstance(self.code, six.string_types):
                    return ctx.eval(self.code)
                elif isinstance(self.code, PyV8.JSFunction):
                    return self.code()
                else:
                    log.warning("Error while handling Window timer")
                    return

            if self.repeat:
                self.start()
        
    def __init__(self, url, dom_or_doc, navigator = None, personality = 'winxpie60', name="", 
                 target='_blank', parent = None, opener = None, replace = False, screen = None, 
                 width = 800, height = 600, left = 0, top = 0, **kwds):

        self.url = url
        self.doc = w3c.getDOMImplementation(dom_or_doc, **kwds) if isinstance(dom_or_doc, BeautifulSoup.BeautifulSoup) else dom_or_doc
        
        self.doc.window        = self
        self.doc.contentWindow = self
         
        self._navigator = navigator if navigator else Navigator(personality, self)
        self._location  = Location(self)
        self._history   = History(self)
        self._history.update(url, replace)

        #self.doc.location = self._location
        self.doc.location = property(self.getLocation, self.setLocation)

        self._target = target
        self._parent = parent if parent else self
        self._opener = opener
        self._screen = screen or Screen(width, height, 32)
        self._closed = False
        
        self._personality = personality
        self.__init_personality()

        self.name          = name
        self.defaultStatus = ""
        self.status        = ""
        self._left         = left
        self._top          = top
        self.innerWidth    = width
        self.innerHeight   = height
        self.outerWidth    = width
        self.outerHeight   = height
        self.timers        = []
        self.java          = java()

        self._symbols      = set()

        log.MIMEHandler.window = self

    def __getattr__(self, key):
        if log.ThugOpts.Personality.isIE() and key.lower() in ('wscript', ):
            # Prevent _ActiveXObject loops
            super(Window, self).__setattr__("WScript", None)

            WScript = _ActiveXObject(self, "WScript.Shell")
            super(Window, self).__setattr__(key, WScript)
            super(Window, self).__setattr__("WScript", WScript)
            return WScript

        return super(Window, self).__getattr__(key)

    @property 
    def closed(self):
        return self._closed

    def close(self):
        self._closed = True

    @property
    def this(self):
        return self

    @property
    def window(self):
        return self

    @property
    def self(self):
        return self

    @property
    def top(self):
        return self

    @property
    def document(self):
        return self.doc

    def _findAll(self, tags):
        return self.doc.doc.find_all(tags, recursive = True)

    @property
    def frames(self):
        """an array of all the frames (including iframes) in the current window"""
        return HTMLCollection(self.doc, [self.doc.createHTMLElement(self.doc, f) for f in self._findAll(['frame', 'iframe'])])

    @property
    def length(self):
        """the number of frames (including iframes) in a window"""
        return len(self._findAll(['frame', 'iframe']))

    @property
    def history(self):
        """the History object for the window"""
        return self._history

    def getLocation(self):
        """the Location object for the window"""
        return self._location

    def setLocation(self, location):
        self._location.href = location

    location = property(getLocation, setLocation)

    @property
    def navigator(self):
        """the Navigator object for the window"""
        return self._navigator

    @property
    def opener(self):
        """a reference to the window that created the window"""
        return self._opener

    @property
    def pageXOffset(self):
        return 0

    @property
    def pageYOffset(self):
        return 0

    @property
    def parent(self):
        return self._parent

    @property
    def screen(self):
        return self._screen
        
    @property
    def screenLeft(self):
        return self._left

    @property
    def screenTop(self):
        return self._top

    @property
    def screenX(self):
        return self._left

    @property
    def screenY(self):
        return self._top

    def _do_ActiveXObject(self, cls, typename = 'name'):
        return _ActiveXObject(self, cls, typename)

    # Window object methods
    #
    # escape        Encodes a string.
    # sizeToContent Sizes the window according to its content.
    # unescape      Unencodes a value that has been encoded in hexadecimal (e.g., a cookie).

    def alert(self, text):
        """
        Display an alert dialog with the specified text.
        Syntax

        window.alert(text) 

        Parameters

        text is a string of the text you want displayed in the alert dialog.
        """
        log.warning('[Window] Alert Text: %s', str(text))

    def back(self):
        """
        Returns the window to the previous item in the history.
        Syntax

        window.back() 

        Parameters

        None.
        """
        pass

    def blur(self):
        """
        Shifts focus away from the window.
        Syntax

        window.blur() 

        Parameters

        None.
        """
        pass

    def captureEvents(self, eventType):
        """
        Registers the window to capture all events of the specified type.
        Syntax

        window.captureEvents(Event.eventType) 

        Parameters

        eventType is a string
        """
        self.alert("[Captured Event] %s" % (eventType, ))

    def clearInterval(self, intervalID):
        """
        Clears a delay that's been set for a specific function.
        Syntax

        window.clearInterval(intervalID) 

        Parameters

        intervalID is the ID of the specific interval you want to clear.
        """
        self.timers[intervalID].stop()

    def clearTimeout(self, timeoutID):
        """
        Clears the delay set by window.setTimeout().
        Syntax

        window.clearTimeout(timeoutID) 

        Parameters

        timeoutID is the ID of the timeout you wish you clear.
        """
        self.timers[timeoutID].stop()
    
    def confirm(self, text):
        """
        Displays a dialog with a message that the user needs to respond to.
        Syntax

        result = window.confirm(text) 

        Parameters

        text is a string.

        result is a boolean value indicating whether OK or Cancel was selected.
        """
        return True

    def dump(self, text):
        """
        Prints messages to the console.
        Syntax

        window.dump(text) 

        Parameters

        text is a string.
        """
        self.alert(text)

    def focus(self):
        """
        Sets focus on the window.
        Syntax

        window.focus() 

        Parameters

        None.
        """
        pass
    
    def forward(self):
        """
        Moves the window one document forward in the history.
        Syntax

        window.forward() 

        Parameters

        None.
        """
        self._history.forward()

    def GetAttention(self):
        """
        Flashes the application icon to get the user's attention.
        Syntax

        window.GetAttention() 

        Parameters

        None.
        """
        pass

    def getSelection(self):
        """
        Returns the selection (generally text).
        Syntax

        selection = window.getSelection() 

        Parameters

        selection is a selection object.
        """
        return None

    def home(self):
        """
        Returns the window to the home page.
        Syntax

        window.home() 

        Parameters

        None.
        """
        self.open()

    def moveBy(self, deltaX, deltaY):
        """
        Moves the current window by a specified amount.
        Syntax

        window.moveBy(deltaX, deltaY) 

        Parameters

        deltaX is the amount of pixels to move the window horizontally.
        deltaY is the amount of pixels to move the window vertically.
        """
        pass

    def moveTo(self, x, y):
        """
        Moves the window to the specified coordinates.
        Syntax

        window.moveTo(x, y) 

        Parameters

        x is the horizontal coordinate to be moved to.
        y is the vertical coordinate to be moved to.
        """
        pass
    
    def prompt(self, text):
        """
        Returns the text entered by the user in a prompt dialog. 
        """
        return text

    def releaseEvents(self, eventType):
        """
        Releases the window from trapping events of a specific type.
        Syntax

        window.releaseEvents(Event.eventType) 

        Parameters

        eventType is a string
        """
        self.alert("[Released Event] %s" % (eventType, ))

    def resizeBy(self, xDelta, yDelta):
        """
        Resizes the current window by a certain amount.
        Syntax

        window.resizeBy(xDelta, yDelta) 

        Parameters

        xDelta is the number of pixels to grow the window horizontally.
        yDelta is the number of pixels to grow the window vertically.
        """
        pass

    def resizeTo(self, iWidth, iHeight):
        """
        Dynamically resizes window.
        Syntax

        window.resizeTo(iWidth, iHeight) 

        Parameters

        iWidth is an integer representing the new width in pixels.
        iHeight is an integer value representing the new height in pixels.
        """
        pass

    def scroll(self, x, y):
        """
        Scrolls the window to a particular place in the document.
        Syntax

        window.scroll(x-coord, y-coord) 

        Parameters

        x-coord is the pixel along the horizontal axis of the document that
        you want displayed in the upper left.
        y-coord is the pixel along the vertical axis of the document that you
        want displayed in the upper left.
        """
        pass

    def scrollBy(self, xDelta, yDelta):
        """
        Scrolls the document in the window by the given amount.
        Syntax

        window.scrollBy(xDelta, yDelta) 

        Parameters

        xDelta is the amount of pixels to scroll horizontally.

        yDelta is the amount of pixels to scroll vertically.
        """
        pass
    
    def scrollByLines(self, lines):
        """
        Scrolls the document by the given number of lines.
        Syntax

        window.scrollByLines(lines) 

        Parameters

        lines is the number of lines.
        """
        pass

    def scrollByPages(self, pages):
        """
        Scrolls the current document by the specified number of pages.
        Syntax

        window.scrollByPages(pages) 

        Parameters

        pages is the number of pages to scroll.
        """
        pass

    def scrollTo(self, x, y):
        """
        Scrolls to a particular set of coordinates in the document.
        Syntax

        window.scrollTo(x-coord, y-coord) 

        Parameters

        x-coord is the pixel along the horizontal axis of the document that you
        want displayed in the upper left.

        y-coord is the pixel along the vertical axis of the document that you
        want displayed in the upper left.
        """
        pass

    def setCursor(self, s):
        pass

    def setInterval(self, f, delay, lang = 'JavaScript'):
        """
        Set a delay for a specific function.
        Syntax

        ID = window.setInterval("funcName", delay)

        Parameters

        funcName is the name of the function for which you want to set a
        delay.

        delay is the number of milliseconds (thousandths of a second)
        that the function should be delayed.

        ID is the interval ID.
        """
        if log.ThugOpts.delay:
            delay = min(delay, log.ThugOpts.delay)

        timer = Window.Timer(self, f, delay, True, lang)
        self.timers.append(timer)
        timer.start()

        return len(self.timers) - 1 

    def setTimeout(self, f, delay = 0, lang = 'JavaScript'):
        """
        Sets a delay for executing a function.
        Syntax

        ID = window.setTimeout("funcName", delay) 

        Parameters

        funcName is the name of the function for which you want to set a
        delay.

        delay is the number of milliseconds (thousandths of a second)
        that the function should be delayed.

        ID is the interval ID.
        """
        if log.ThugOpts.delay:
            delay = min(delay, log.ThugOpts.delay)

        timer = Window.Timer(self, f, delay, False, lang)
        self.timers.append(timer)
        timer.start()

        return len(self.timers) - 1

    def stop(self):
        """
        This method stops window loading.
        Syntax

        window.stop() 

        Parameters

        None.
        """
        pass
                
    def _attachEvent(self, sEvent, fpNotify, useCapture = False):
        log.debug("[attachEvent] %s %s", sEvent, fpNotify)
        setattr(self, sEvent.lower(), fpNotify)
    
    def _detachEvent(self, sEvent, fpNotify):
        log.debug("[detachEvent] %s %s", sEvent, fpNotify)
        notify = getattr(self, sEvent.lower(), None)
        if notify is None:
            return
    
        if notify in (fpNotify, ):
            delattr(self, sEvent.lower())
    
    def _addEventListener(self, _type, listener, useCapture = False):
        log.debug("[addEventListener] %s %s %s", _type, listener, useCapture)
        setattr(self, 'on%s' % (_type.lower(), ), listener)
    
    def _removeEventListener(self, _type, listener, useCapture = False):
        log.debug("[removeEventListener] %s %s %s", _type, listener, useCapture)
        _listener = getattr(self, 'on%s' % (_type.lower(), ), None)
        if _listener is None:
            return
    
        if _listener in (listener, ):
            delattr(self, 'on%s' % (_type.lower(), ))

    def _CollectGarbage(self):
        pass

    def _navigate(self, location):
        self.location = location
        return 0

    def __init_personality(self):
        if log.ThugOpts.Personality.isIE():
            self.__init_personality_IE()
            return

        if log.ThugOpts.Personality.isFirefox():
            self.__init_personality_Firefox()
            return

        if log.ThugOpts.Personality.isChrome():
            self.__init_personality_Chrome()
            return

        if log.ThugOpts.Personality.isSafari():
            self.__init_personality_Safari()
            return

        if log.ThugOpts.Personality.isOpera():
            self.__init_personality_Opera()

    def __init_personality_IE(self):
        self.ActiveXObject     = self._do_ActiveXObject
        self.CollectGarbage    = self._CollectGarbage
        self.navigate          = self._navigate
        self.clientInformation = self.navigator
        self.clipboardData     = ClipboardData()
        self.external          = External()
        #_ActiveXObject(self, "WScript.Shell")

        if log.ThugOpts.Personality.browserMajorVersion < 9:
            self.attachEvent = self._attachEvent
            self.detachEvent = self._detachEvent
        else:
            self.addEventListener    = self._addEventListener
            self.removeEventListener = self._removeEventListener

        if log.ThugOpts.Personality.browserMajorVersion >= 8:
            self.localStorage   = LocalStorage()
            self.sessionStorage = SessionStorage()

        self.doc.parentWindow = self._parent

    def __init_personality_Firefox(self):
        self.addEventListener    = self._addEventListener
        self.removeEventListener = self._removeEventListener
        self.crypto              = Crypto()
        self.sidebar             = Sidebar()
        self.Components          = Components()
        self.console             = Console()
        self.localStorage        = LocalStorage()
        self.sessionStorage      = SessionStorage()

    def __init_personality_Chrome(self):
        self.addEventListener    = self._addEventListener
        self.removeEventListener = self._removeEventListener
        self.clientInformation   = self.navigator
        self.external            = External()
        self.chrome              = Chrome()
        self.console             = Console()
        self.localStorage        = LocalStorage()
        self.sessionStorage      = SessionStorage()

    def __init_personality_Safari(self):
        self.addEventListener    = self._addEventListener
        self.removeEventListener = self._removeEventListener
        self.clientInformation   = self.navigator
        self.console             = Console()
        self.localStorage        = LocalStorage()
        self.sessionStorage      = SessionStorage()

    def __init_personality_Opera(self):
        self.addEventListener    = self._addEventListener
        self.removeEventListener = self._removeEventListener
        self.opera               = Opera()
        self.doc.parentWindow    = self._parent
        self.console             = Console()
        self.localStorage        = LocalStorage()
        self.sessionStorage      = SessionStorage()

    def eval(self, script):
        if script is None:
            return

        if len(script) > 4:
            try:
                log.info(jsbeautifier.beautify(script))
            except: #pylint:disable=bare-except
                log.info(script)

        if len(script) > 64: 
            log.warning("[Window] Eval argument length > 64 (%d)", len(script))

        if len(script) > 4:
            log.ThugLogging.add_code_snippet(script, 'Javascript', 'Dynamically_Evaluated', True)

        return self.evalScript(script)

    @property
    def context(self):
        #if not hasattr(self, '_context'):
        if '_context' not in self.__dict__:
            self._context = PyV8.JSContext(self)
            with self._context as ctxt:
                thug_js = os.path.join(thug.__configuration_path__, 'scripts', "thug.js")
                ctxt.eval(open(thug_js, 'r').read())

                if log.ThugOpts.Personality.isIE() and log.ThugOpts.Personality.browserMajorVersion < 8:
                    storage_js = os.path.join(thug.__configuration_path__, 'scripts', "storage.js")
                    ctxt.eval(open(storage_js, 'r').read())

                PyV8.JSEngine.collect()

        return self._context

    def evalScript(self, script, tag = None):
        result = 0

        try:
            log.JSClassifier.classify('[Local analysis]' if log.ThugOpts.local else self.url,
                                      script)
        except: #pylint:disable=bare-except
            pass

        if tag:
            self.doc.current = tag
        else:
            try:
                body = self.doc.body
            except: #pylint:disable=bare-except
                # This code is for when you are desperate :)
                body = self.doc.getElementsByTagName('body')[0]

            if body and body.tag.contents:
                self.doc.current = body.tag.contents[-1]
            else:
                self.doc.current = self.doc.doc.contents[-1]

        with self.context as ctxt:
            try:
                ast = AST(self, script)
            except: #pylint:disable=bare-except
                log.debug(traceback.format_exc())
                return result

            if log.ThugOpts.Personality.isIE():
                cc = CCInterpreter()
                script = cc.run(script)

            shellcode = Shellcode.Shellcode(self, ctxt, ast, script)
            result    = shellcode.run()

        return result

    def unescape(self, s):
        i  = 0 
        sc = list()

        if len(s) > 16:
            log.ThugLogging.shellcodes.add(s)

        # %xx format
        if '%' in s and '%u' not in s:
            return urllib.unquote(s)

        # %uxxxx format
        while i < len(s):
            if s[i] == '"':
                i += 1
                continue

            if s[i] == '%' and (i + 1) < len(s) and  s[i + 1] == 'u':
                if (i + 6) <= len(s):
                    currchar = int(s[i + 2: i + 4], 16) 
                    nextchar = int(s[i + 4: i + 6], 16) 
                    sc.append(chr(nextchar))
                    sc.append(chr(currchar))
                    i += 6
                elif (i + 3) <= len(s):
                    currchar = int(s[i + 2: i + 4], 16) 
                    sc.append(chr(currchar))
                    i += 3
            else:
                sc.append(s[i])
                i += 1

        return ''.join(sc)

    def Image(self, width = 800, height = 600):
        return self.doc.createElement('img')

    def XMLHttpRequest(self):
        return _ActiveXObject(self, 'microsoft.xmlhttp')

    def getComputedStyle(self, element, pseudoelt = None):
        return getattr(element, 'style', None)

    def open(self, url = None, name = '_blank', specs = '', replace = False):
        if url:
            try:
                response = self._navigator.fetch(url, redirect_type = "window open")
            except: #pylint:disable=bare-except
                #traceback.print_exc()
                return None

            if response is None:
                return None

            if response.status_code == 404:
                return None

            html = response.content

            if response.history:
                url = response.url

            content_type = response.headers.get('content-type' , None)
            if content_type:
                handler = log.MIMEHandler.get_handler(content_type)
                if handler and handler(url, html):
                    return None

            # Log response here
            kwds = { 'referer' : self.url }
            if 'set-cookie' in response.headers:
                kwds['cookie'] = response.headers['set-cookie']
            if 'last-modified' in response.headers:
                kwds['lastModified'] = response.headers['last-modified']
        else:
            url  = 'about:blank'
            html = ''
            kwds = {}
       
        dom = BeautifulSoup.BeautifulSoup(html, "html5lib")
        
        for spec in specs.split(','):
            spec = [s.strip() for s in spec.split('=')]

            if len(spec) == 2:
                if spec[0] in ['width', 'height', 'left', 'top']:
                    kwds[spec[0]] = int(spec[1])

            if name in ['_blank', '_parent', '_self', '_top']:
                kwds['target'] = name
                name = ''
            else:
                kwds['target'] = '_blank'

        return Window(url, dom, navigator = None, personality = self._personality, 
                        name = name, parent = self, opener = self, replace = replace, **kwds)
