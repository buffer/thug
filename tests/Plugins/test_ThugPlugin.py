import sys

from thug.thug import Thug
from thug.Plugins import ThugPlugins

PHASE = 'PRE'

THUG = Thug([])
ThugPlugins.PLUGINS_PATH = "thug/Plugins/plugins/"
PLUGINS = ThugPlugins.ThugPlugins(PHASE, THUG)


sys.path.append(ThugPlugins.PLUGINS_PATH)


class TestThugPlugin():
    def test_get_plugin_low_prio(self):
        plugin_info = ['TestPlugin', 'example']
        assert PLUGINS.get_plugin_prio(plugin_info) == 1000

    def test_get_plugin_high_prio(self):
        plugin_info = ['POST', 'TestPlugin', '999']
        assert PLUGINS.get_plugin_prio(plugin_info) == 999

        #Test Value error in try/except
        plugin_info = ['POST','999', 'TestPlugin']
        assert PLUGINS.get_plugin_prio(plugin_info) == 1001

    def test_get_plugin(self):
        PLUGINS.get_plugins()
        expected = [('PRE-TestPlugin-999', 999)]
        assert PLUGINS.plugins == expected

    def test_run(self):
        self.expected = ('TestPlugin', 'PRE', 999)

        # Create mock object for log
        class mock_log():
            def __init__(self):
                self.data = []

            def warning(self, *args):
                self.data.append(args)

            def debug(self, *args):
                pass

        ThugPlugins.log = mock_log()
        PLUGINS.run()

        mock_data = ThugPlugins.log.data[0]
        assert mock_data[1:4] == self.expected
