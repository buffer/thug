from thug.ThugAPI.Watchdog import Watchdog


class TestWatchDog:
    def test_watch(self):
        with Watchdog(600):
            pass
