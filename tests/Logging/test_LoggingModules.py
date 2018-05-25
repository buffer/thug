import thug.Logging.LoggingModules as log_modules


def test_maec():
    assert log_modules.LoggingModules['maec11'] is log_modules.MITRE.MAEC11


def test_json():
    assert log_modules.LoggingModules['json'] is log_modules.JSON.JSON


def test_mongodb():
    assert log_modules.LoggingModules['mongodb'] is log_modules.MongoDB.MongoDB


def test_elasticsearch():
    assert log_modules.LoggingModules['elasticsearch'] is log_modules.ElasticSearch.ElasticSearch


def test_hpfeeds():
    assert log_modules.LoggingModules['hpfeeds'] is log_modules.HPFeeds.HPFeeds
