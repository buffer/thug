import sys
import os
from behave import *
from behave.log_capture import capture

THUG = os.path.dirname(os.path.abspath(__file__)).split("samples")[0]
MISC = os.path.join(THUG, 'samples', 'misc')
sys.path.append(os.path.join(THUG, 'src'))

from ThugAPI import ThugAPI

class Misc(object):
    def __init__(self, context):
        self.misc = list()
        for row in context.table:
            self.misc.append(row)

    def _run(self, context, exploit):
        sample = os.path.join(MISC, exploit[0])

        instance = ThugAPI(None, None)
        instance.set_events('click')
        instance.set_timeout(1)
        instance.log_init(sample)
        instance.run_local(sample)

        for assertion in exploit[1].split(","):
            assert assertion in context.log_capture.getvalue()

    def run(self, context):
        for misc in self.misc:
            self._run(context, misc)

@given('set of misc')
def step_impl(context):
    global misc 
    misc = Misc(context)

@capture
@then('run misc')
def step_impl(context):
    misc.run(context)
