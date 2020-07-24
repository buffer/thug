import sys
import os
from behave import *
from behave.log_capture import capture

THUG = os.path.dirname(os.path.abspath(__file__)).split("thug")[0]
MISC = os.path.join(THUG, 'thug', 'samples', 'misc')
sys.path.append(os.path.join(THUG, 'src'))

from thug.ThugAPI.ThugAPI import ThugAPI

class Misc(ThugAPI):
    def __init__(self, context):
        ThugAPI.__init__(self)

        self.misc = list()
        for row in context.table:
            self.misc.append(row)

    def _run_step(self, context, exploit):
        sample = os.path.join(MISC, exploit[0])

        self.set_useragent('win7ie90')
        self.set_events('click,storage')
        self.disable_cert_logging()
        self.log_init(sample)
        self.run_local(sample)

        for assertion in exploit[1].split(","):
            assert assertion in context.log_capture.getvalue()

    def run_step(self, context):
        for misc in self.misc:
            self._run_step(context, misc)

@given('set of misc')
def step_impl(context):
    global misc
    misc = Misc(context)

@capture
@then('run misc')
def step_impl(context):
    misc.run_step(context)
