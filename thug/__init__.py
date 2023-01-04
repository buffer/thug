import os

import appdirs

__version__            = "4.7"
__jsengine__           = ""
__jsengine_version__   = ""

__global_configuration_path__ = "/etc/thug"
if os.path.exists(__global_configuration_path__):
    __configuration_path__ = __global_configuration_path__
else:
    __configuration_path__ = f"{appdirs.user_config_dir()}/thug" # pragma: no cover

__personalities_path__ = os.path.join(__configuration_path__, "personalities")
__rules_path__         = os.path.join(__configuration_path__, "rules")
__scripts_path__       = os.path.join(__configuration_path__, "scripts")
__plugins_path__       = os.path.join(__configuration_path__, "plugins")
__hooks_path__         = os.path.join(__configuration_path__, "hooks")

__html_rules_path__    = os.path.join(__rules_path__, "htmlclassifier")
__js_rules_path__      = os.path.join(__rules_path__, "jsclassifier")
__vbs_rules_path__     = os.path.join(__rules_path__, "vbsclassifier")
__url_rules_path__     = os.path.join(__rules_path__, "urlclassifier")
__sample_rules_path__  = os.path.join(__rules_path__, "sampleclassifier")
__text_rules_path__    = os.path.join(__rules_path__, "textclassifier")
__cookie_rules_path__  = os.path.join(__rules_path__, "cookieclassifier")
__image_rules_path__   = os.path.join(__rules_path__, "imageclassifier")
__html_filter_path__   = os.path.join(__rules_path__, "htmlfilter")
__js_filter_path__     = os.path.join(__rules_path__, "jsfilter")
__vbs_filter_path__    = os.path.join(__rules_path__, "vbsfilter")
__url_filter_path__    = os.path.join(__rules_path__, "urlfilter")
__sample_filter_path__ = os.path.join(__rules_path__, "samplefilter")
__text_filter_path__   = os.path.join(__rules_path__, "textfilter")
__cookie_filter_path__ = os.path.join(__rules_path__, "cookiefilter")
__image_filter_path__  = os.path.join(__rules_path__, "imagefilter")


try:
    import STPyV8

    __jsengine__         = "Google V8"
    __jsengine_version__ = getattr(STPyV8, "__version__", "")
except ImportError: # pragma: no cover
    pass
