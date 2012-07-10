
Plugin Framework
================

The Thug Plugin Framework was introduced in the version 0.3.0. If you ever thought about extending Thug 
with additional features but didn’t know how to do it you should really keep on reading. Let’s start 
by taking a look a the code.

Taking a look at *src/thug.py* we can now read these lines of code

.. code-block:: python
 
        if p:
                ThugPlugins(PRE_ANALYSIS_PLUGINS, self)()
                p(args[0])
                ThugPlugins(POST_ANALYSIS_PLUGINS, self)()
 
Please note that every operation done by Thug is started by the line *p(args[0])* so you can realize that 
two hooks exist in order to execute plugins in a pre and post-analysis stage. Let’s keep exploring the 
source code and let’s take a look at *src/Plugins/ThugPlugins.py*.
 

.. code-block:: python

        class ThugPlugins:
                phases = {
                        PRE_ANALYSIS_PLUGINS  : 'ThugPluginsPre',
                        POST_ANALYSIS_PLUGINS : 'ThugPluginsPost'
                        }

                def __init__(self, phase, thug):
                        self.phase = phase
                        self.thug  = thug
                        self.__init_config()

                def __init_config(self):
                        self.plugins = set()
                        config       = ConfigParser.ConfigParser()

                        conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugins.conf')
                        config.read(conf_file)

                        plugins = config.get(self.phases[self.phase], 'plugins')
                        for plugin in plugins.split(','):
                                self.plugins.add(plugin.strip())

                def __call__(self):
                        self.run()

                def run(self):
                        for source in self.plugins:
                                module = __import__(source)
                                components = source.split('.')
                                for component in components[1:]:
                                        module = getattr(module, component)

                                handler = getattr(module, "Handler", None)
                                if handler:
                                        p = handler()
                                        try:
                                                verifyObject(IPlugin, p)
                                                p.run(self.thug, log)
                                        except BrokenImplementation as e:
                                                log.warning("[%s] %s" % (source, e, ))

 
and *src/Plugins/plugins.conf*
 
.. code-block:: sh

        [ThugPluginsPre]
        plugins: Plugins.TestPlugin

        [ThugPluginsPost]
        plugins: Plugins.TestPlugin
 
The configuration file plugins.conf defines which plugins are to be loaded in pre and post-analysis 
stage (you can specify many plugins by simply comma separating them). The plugins should contain a 
class named *Handler* which should be conform to this interface

.. code-block:: python
 
        class IPlugin(zope.interface.Interface):
                def run(thug, log):
                """
                This method is called when the plugin is invoked

                Parameters:
                @thug: Thug class main instance
                @log: Thug root logger
                """
 
If the interface is correctly implemented the *run* method is called with two parameters: the Thug class 
main instance and the Thug root logger. Let’s see a really simple example of plugin

.. code-block:: python
 
        import zope.interface
        from .IPlugin import IPlugin

        class Handler:
                zope.interface.implements(IPlugin)

                def run(self, thug, log):
                        log.debug(thug)
                        log.debug(log)
 
This plugin just logs the parameters but you can do whatever you want. Do you want to pre-check if the URL 
domain is within a blacklist? Just do it with a pre-analysis plugin. Do you want to extract and/or correlate 
information from the MAEC log files? Just do it with a post-analysis plugin. Simply staten... have fun!
