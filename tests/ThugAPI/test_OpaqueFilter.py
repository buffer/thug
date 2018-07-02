from thug.ThugAPI.OpaqueFilter import OpaqueFilter


class TestOpaqueFilter:
    opaque_filter = OpaqueFilter()

    def test_filter(self):
        assert not self.opaque_filter.filter('sample-record')
