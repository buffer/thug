import thug

from thug.Logging.modules.Mapper import DictDiffer
from thug.Logging.modules.Mapper import Mapper


class TestDictDiffer:
    """
        Unittests for the methods of class DictDiffer

        @curr_dict:  1) Value for k1 key is changed from v2 to v1
                        2) k3 key is added
                        3) k5 key is removed
    """

    curr_dict = {'k1': 'v1', 'k2': 'v2', 'k3': 'v3', 'k4': 'v4'}
    past_dict = {'k1': 'v2', 'k2': 'v2', 'k4': 'v4', 'k5': 'v5'}
    dict_differ = DictDiffer(curr_dict, past_dict)

    def test_added(self):
        added_keys = self.dict_differ.added()
        assert {'k3'} in (added_keys, )

    def test_removed(self):
        removed_keys = self.dict_differ.removed()
        assert {'k5'} in (removed_keys, )

    def test_changed(self):
        changed_keys = self.dict_differ.changed()
        assert {'k1'} in (changed_keys, )

    def test_unchanged(self):
        unchanged_keys = self.dict_differ.unchanged()
        assert {'k2', 'k4'} in (unchanged_keys, )

    def test_anychange(self):
        assert not self.dict_differ.anychange()
        assert DictDiffer(self.curr_dict, self.curr_dict).anychange()


class TestMapper:
    mapper = Mapper("sample-mapper-dir")

    markup_loc = {'content-type': 'text/html'}
    image_loc = {'content-type': 'image/'}
    exec_loc = {'content-type': 'application/javascript'}

    def test_check_markup(self):
        assert self.mapper.check_markup(self.markup_loc)

    def test_check_image(self):
        assert not self.mapper.check_image(self.markup_loc)

    def test_check_exec(self):
        assert not self.mapper.check_exec(self.markup_loc)

    def test_get_shape(self):
        shape = self.mapper.get_shape(self.markup_loc)
        assert 'box' in (shape, )

        shape = self.mapper.get_shape(self.image_loc)
        assert 'oval' in (shape, )

        shape = self.mapper.get_shape(self.exec_loc)
        assert 'hexagon' in (shape, )

    def test_get_fillcolor(self):
        pass

    def test_get_color(self):
        pass

    def test_normalize_url(self):
        pass

    def test_dot_from_data(self):
        pass

    def test_add_location(self):
        pass

    def test_add_weak_location(self):
        pass

    def test_add_connection(self):
        pass

    def test_add_data(self):
        pass

