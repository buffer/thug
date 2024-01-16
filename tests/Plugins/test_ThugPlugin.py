import sys

from thug.thug import Thug
from thug.Plugins import ThugPlugins

THUG = Thug([])
ThugPlugins.PLUGINS_PATH = "thug/Plugins/plugins/"

PRE_PLUGINS = ThugPlugins.ThugPlugins("PRE", THUG)
POST_PLUGINS = ThugPlugins.ThugPlugins("POST", THUG)

sys.path.append(ThugPlugins.PLUGINS_PATH)


class TestThugPlugin:
    def test_get_plugin_low_prio(self):
        plugin_info = ["TestPlugin", "example"]
        assert PRE_PLUGINS.get_plugin_prio(plugin_info) == 1000

    def test_get_plugin_high_prio(self):
        plugin_info = ["POST", "TestPlugin", "999"]
        assert PRE_PLUGINS.get_plugin_prio(plugin_info) == 999

        # Testing ValueError exception
        plugin_info = ["POST", "999", "TestPlugin"]
        assert PRE_PLUGINS.get_plugin_prio(plugin_info) == 1001

    def test_get_plugin(self):
        PRE_PLUGINS.get_plugins()
        expected = [("PRE-TestPlugin-999", 999)]
        assert PRE_PLUGINS.plugins == expected

        POST_PLUGINS.get_plugins()
        expected = [("POST-TestPlugin-999", 999)]
        assert POST_PLUGINS.plugins == expected

    def test_run(self):
        self.expected = ("TestPlugin", "PRE", 999)

        # Create mock object for log
        class mock_log:
            def __init__(self):
                self.data = []

            def warning(self, *args):
                self.data.append(args)

            def debug(self, *args):
                pass

        ThugPlugins.log = mock_log()
        PRE_PLUGINS.run()

        mock_data = ThugPlugins.log.data[0]
        assert mock_data[1:4] == self.expected

        POST_PLUGINS.run()
