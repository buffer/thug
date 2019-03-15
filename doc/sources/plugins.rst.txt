
Plugin Framework
================

The Thug Plugin Framework was introduced in version 0.3.0 and totally redesigned in version 0.8.1. If you ever thought 
about extending Thug with additional features but do not know how to do it you should really keep on reading. 

Let's start by taking a look a the code. Taking a look at *thug/thug.py* we can read these lines of code

.. code-block:: python
 
        if p:
                ThugPlugins(PRE_ANALYSIS_PLUGINS, self)()
                p(args[0])
                ThugPlugins(POST_ANALYSIS_PLUGINS, self)()
 
Every operation performed by Thug is started by the line *p(args[0])* so you can realize that two hooks exist in order 
to execute plugins in a pre and post-analysis stage. Please note that you can use the same approach even if developing
external tools based on Thug API.

Let's take a look at how to use the Plugin Framework before diving deep into details of how to write a plugin. During
the Thug installation process the (empty) directory */etc/thug/plugins* is created automatically. Moreover, take 
a look at the directory *thug/thug/Plugins/plugins* in the source tree 

.. code-block:: sh

    ~/thug/thug/Plugins/plugins $ ls -lhR
    .:
    total 0
    drwxr-xr-x 2 buffer buffer 41 Oct 12 09:00 POST-TestPlugin-999
    drwxr-xr-x 2 buffer buffer 41 Oct 12 09:00 PRE-TestPlugin-999

    ./POST-TestPlugin-999:
    total 4.0K
    -rw-r--r-- 1 buffer buffer 885 Oct 12 09:00 Handler.py
    -rw-r--r-- 1 buffer buffer   0 Oct 12 09:00 __init__.py

    ./PRE-TestPlugin-999:
    total 4.0K
    -rw-r--r-- 1 buffer buffer 885 Oct 12 09:00 Handler.py
    -rw-r--r-- 1 buffer buffer   0 Oct 12 09:00 __init__.py

The directories *PRE-TestPlugin-999* and *POST-TestPlugin-999* contains the plugins we will be using for the next
examples.

Before moving on, some details about the plugin directory name convention. The Plugin Framework expects the directory
names in the following format for high-priority plugins: 

.. code-block:: sh

    [PHASE]-[PLUGIN NAME]-[PRIORITY]
    
or the following one for low-priority plugins (more on that later)

.. code-block:: sh

    [PHASE]-[PLUGIN NAME]

where 

* PHASE specifies if the plugin has to be executed in a pre or post-analysis stage (possible values: 'PRE', 'POST')
* PLUGIN_NAME specifies the name of the plugin
* PRIORITY (optional) defines the plugin priority

If the plugin priority is specified (high-priority plugin), its value should be between 1 and 999. Plugin priority values
greater or equal than 1000 are reserved for low-priority plugins and a plugin which does not specify a priority will be
automatically assigned a priority value in such range. The plugin priority is useful if you want to enforce a specific
order of execution for your plugins. For instance, if plugin B requires plugin A to operate on data before performing
its task all you need to do is to define the plugin directory names this way

.. code-block:: sh

    PRE-PluginA-1
    PRE-PluginB-2

and the Plugin Framework guarantees that plugin A will be always executed before plugin B. Note that this applies to
post-analysis plugins as well. 

Assigning two (or more) high-priority plugins the same priority is possible. Both plugins will be executed but the 
framework can not guarantee their relative order of execution.

If you respect the convention of the specifically assigned priority value between 1 and 999, not assigning a priority 
to a plugin will make it a low-priority plugin meaning that it will be executed after all the high-priority plugins. 
If you define two or more low-priority plugins, there is no guarantee about their relative order of execution but 
they will executed after the high-priority ones in any case.

The suggested practice is to always assign a priority to each and every plugin in order to effectively control their 
relative order of execution.        

Let's take a look at how to use the Plugin Framework. 
 
.. code-block:: sh

    /etc/thug/plugins $ ls -lh
    total 0
    ~/thug/thug $ thug -l ../samples/exploits/22811_Elazar.html 
    [2016-10-12 09:46:21] ActiveXObject: ierpctl.ierpctl
    [2016-10-12 09:46:21] [RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in Import
    [2016-10-12 09:46:21] [RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in PlayerProperty

Let's try again after copying one of the test plugin directories provided in the source tree

.. code-block:: sh

    ~/thug/thug $ sudo cp -dpR Plugins/plugins/PRE-TestPlugin-999/ /etc/thug/plugins/
    ~/thug/thug $ ls -lh /etc/thug/plugins/
    total 0
    drwxr-xr-x 2 buffer buffer 41 Oct 12 09:00 PRE-TestPlugin-999
    ~/thug/thug $ thug -l ../samples/exploits/22811_Elazar.html 
    [2016-10-12 09:48:53] [PLUGIN][TestPlugin] Phase: PRE_ANALYSIS Priority: 999
    [2016-10-12 09:48:53] ActiveXObject: ierpctl.ierpctl
    [2016-10-12 09:48:53] [RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in Import
    [2016-10-12 09:48:53] [RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in PlayerProperty

As you can see, TestPlugin is executed in pre-analysis stage (priority 999) as expected.

Let's try again after copying the other test plugin directory provided in the source tree

.. code-block:: sh

    ~/thug/thug $ sudo cp -dpR Plugins/plugins/POST-TestPlugin-999/ /etc/thug/plugins/
    ~/thug/thug $ ls -lh /etc/thug/plugins/
    total 0
    drwxr-xr-x 2 buffer buffer 41 Oct 12 09:00 POST-TestPlugin-999
    drwxr-xr-x 2 buffer buffer 78 Oct 12 09:48 PRE-TestPlugin-999
    ~/thug/thug $ thug -l ../samples/exploits/22811_Elazar.html 
    [2016-10-12 09:53:16] [PLUGIN][TestPlugin] Phase: PRE_ANALYSIS Priority: 999
    [2016-10-12 09:53:17] ActiveXObject: ierpctl.ierpctl
    [2016-10-12 09:53:17] [RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in Import
    [2016-10-12 09:53:17] [RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in PlayerProperty
    [2016-10-12 09:53:17] [PLUGIN][TestPlugin] Phase: POST_ANALYSIS Priority: 999
 
Both plugins are executed now in pre and post-analysis stage with the correct priorities. So all you
need is to just drop the directory in the */etc/thug/plugins*. But remember that if the directory name
does not follow the convention, it will be just ignored!

The last step is to understand the anatomy of a plugin.

The plugin directory must contain a source file named *Handler.py* and this source file must define
the class named *Handler* (entry point) which should be compliant with the following interface

.. code-block:: python
 
        class IPlugin(zope.interface.Interface):
                def run(thug, log):
                """
                This method is called when the plugin is invoked

                Parameters:
                @thug: Thug class main instance
                @log: Thug root logger
                """
 
If the interface is correctly implemented the *run* method is automatically called passing to it two 
parameters: the Thug class main instance and the Thug root logger. 

Let's see a really simple example of plugin (TestPlugin)

.. code-block:: python
 
        import zope.interface
        from .IPlugin import IPlugin

        @implementer(IPlugin)
        class Handler:
                def run(self, thug, log):
                        log.debug(thug)
                        log.debug(log)
 
This plugin just logs the parameters but you can do whatever you want. Let's try again the previous
example enabling the debug option in order to see the debug messages

.. code-block:: sh

    ~/thug/thug $ thug -l -d ../samples/exploits/22811_Elazar.html 
    [2016-10-12 10:02:13] [PLUGIN][TestPlugin] Phase: PRE_ANALYSIS Priority: 999
    [2016-10-12 10:02:13] <thug.thug.Thug object at 0x7f69b0ca2050>
    [2016-10-12 10:02:13] <logging.Logger object at 0x7f69aa85cdd0>
    [2016-10-12 10:02:13] Handling DOM Events: load,mousemove

    [..]

    [2016-10-12 10:02:13] ActiveXObject: ierpctl.ierpctl
    [2016-10-12 10:02:13] [RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in Import
    [2016-10-12 10:02:13] [RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in PlayerProperty
    [2016-10-12 10:02:13] [PLUGIN][TestPlugin] Phase: POST_ANALYSIS Priority: 999
    [2016-10-12 10:02:13] <thug.thug.Thug object at 0x7f69b0ca2050>
    [2016-10-12 10:02:13] <logging.Logger object at 0x7f69aa85cdd0>


Do you want to pre-check if the URL domain is within a blacklist? Just do it with a pre-analysis plugin. Do 
you want to extract and/or correlate information from the log files? Just do it with a post-analysis plugin.
