from thug.DOM.Plugin import Plugin

class TestPlugin(object):
    def test_items(self):
        plugin = Plugin()

        plugin['test1'] = 'value1'
        assert plugin['test1'] in ('value1', )

        plugin.test2 = 'value2'
        assert plugin.test2 in ('value2', )

        del plugin['test1']
        del plugin.test2

        assert plugin['test3'] is None
        del plugin['test3']
