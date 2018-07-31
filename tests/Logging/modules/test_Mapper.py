import os
import json

from thug.Logging.modules.Mapper import DictDiffer
from thug.Logging.modules.Mapper import Mapper


class TestDictDiffer:
    """
        Unittests for the methods of class DictDiffer

        @curr_dict: 1) Value for k1 key is changed from v2 to v1
                    2) k3 key is added
                    3) k5 key is removed
    """

    curr_dict = {'k1': 'v1', 'k2': 'v2', 'k3': 'v3', 'k4': 'v4'}
    past_dict = {'k1': 'v2', 'k2': 'v2', 'k4': 'v4', 'k5': 'v5'}
    dict_differ = DictDiffer(curr_dict, past_dict)

    def test_added(self):
        added_keys = self.dict_differ.added()
        assert added_keys in ({'k3'}, )

    def test_removed(self):
        removed_keys = self.dict_differ.removed()
        assert removed_keys in ({'k5'},)

    def test_changed(self):
        changed_keys = self.dict_differ.changed()
        assert changed_keys in ({'k1'},)

    def test_unchanged(self):
        unchanged_keys = self.dict_differ.unchanged()
        assert unchanged_keys in ({'k2', 'k4'},)

    def test_anychange(self):
        assert self.dict_differ.anychange()
        assert not DictDiffer(self.curr_dict, self.curr_dict).anychange()


class TestMapper:
    cwd_path  = os.path.dirname(os.path.realpath(__file__))
    json_path = os.path.join(cwd_path, os.pardir, os.pardir, os.pardir, "tests/test_files/Mapper")

    data_file  = os.path.join(json_path, "test_data.json")
    error_file = os.path.join(json_path, "test_error.json")

    data        = json.load(open(data_file, "r"))
    image_loc   = data["locations"][0]
    markup_loc  = data["locations"][1]
    exec_loc    = data["locations"][2]
    unknown_loc = data["locations"][3]

    iframe_con = data["connections"][0]
    link_con   = data["connections"][1]

    mapper = Mapper("sample-mapper-dir", simplify=True)

    def test_get_shape(self):
        shape = self.mapper.get_shape(self.markup_loc)
        assert shape in ('box', )

        shape = self.mapper.get_shape(self.image_loc)
        assert shape in ('oval',)

        shape = self.mapper.get_shape(self.exec_loc)
        assert shape in ('hexagon',)

        assert not self.mapper.get_shape(self.unknown_loc)

    def test_get_fillcolor(self):
        fillcolor = self.mapper.get_fillcolor(self.image_loc)
        assert fillcolor in ("orange", )

        fillcolor = self.mapper.get_fillcolor(self.markup_loc)
        assert not fillcolor

    def test_get_color(self):
        color = self.mapper.get_color(self.iframe_con)
        assert color in ("orange", )

        color = self.mapper.get_color(self.link_con)
        assert not color

    def test_normalize_url(self):
        sample_url = self.image_loc["url"]
        assert self.mapper.normalize_url(sample_url + '/') in (sample_url, )
        assert self.mapper.normalize_url(sample_url) in (sample_url, )

    def test_add_weak_location(self):
        self.mapper.add_weak_location("https://www.ex.com")
        assert len(self.mapper.data["locations"]) in (1, )

    def test_add_file(self):
        self.mapper.add_file(self.data_file)
        assert len(self.mapper.data["locations"]) in (5, )
        assert len(self.mapper.data["connections"]) in (2, )

        # Testing for ValueError because of malformed JSON
        self.mapper.add_file(self.error_file)
        assert len(self.mapper.data["locations"]) in (5, )
        assert len(self.mapper.data["connections"]) in (2, )

    def test_write_text(self):
        con1_string = "www.example.com -- iframe --> www.example2.com \n"
        con2_string = "www.example.com -- link --> www.example1.com \n"
        res = con1_string + con2_string
        assert self.mapper.write_text() in (res, )

    def test_write_svg(self):
        self.mapper.write_svg()
        assert os.path.isfile("graph.svg")

        os.remove("graph.svg")
        assert not os.path.isfile("graph.svg")

    def test_follow_track(self):
        self.mapper.follow_track("www.example2.com")
        self.test_write_svg()
