import sys
import os
from behave import *
from behave.log_capture import capture

THUG = os.path.dirname(os.path.abspath(__file__)).split("samples")[0]
JQUERY = os.path.join(THUG, 'samples', 'jQuery')
sys.path.append(os.path.join(THUG, 'src'))

from thug.ThugAPI.ThugAPI import ThugAPI

class jQuery(ThugAPI):
    def __init__(self, context):
        ThugAPI.__init__(self)

        self.jquery = list()
        for row in context.table:
            self.jquery.append(row)

    def _run_step(self, context, exploit, useragent):
        sample = os.path.join(JQUERY, exploit[0])

        self.set_useragent(useragent)
        self.set_events('click')
        self.disable_code_logging()
        self.disable_cert_logging()
        self.log_init(sample)
        self.run_local(sample)

        for assertion in exploit[1].split(","):
            assert assertion in context.log_capture.getvalue()

    def run_step(self, context):
        for jquery in self.jquery:
            self._run_step(context, jquery, 'win7ie90')
            self._run_step(context, jquery, 'win7chrome49')

@given('set of jquery')
def step_impl(context):
    global jquery
    jquery = jQuery(context)

@capture
@then('run jquery')
def step_impl(context):
    jquery.run_step(context)
