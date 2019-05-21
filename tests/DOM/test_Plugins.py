from thug.DOM.Plugins import Plugins


class TestPlugins(object):
    def test_items(self):
        plugins = Plugins()

        plugins.refresh()

        assert plugins['foo'] is None
        assert plugins[100] is None
