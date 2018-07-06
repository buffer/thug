import pytest

from thug.ThugAPI.abstractmethod import abstractmethod


class SampleClass:
    @abstractmethod
    def sample_method(self):
        pass


def test_error():
    sample = SampleClass()
    with pytest.raises(NotImplementedError) as exc:
        sample.sample_method()
    assert "method sample_method is abstract" in exc.value
