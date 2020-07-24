from thug.DOM.W3C.Views.AbstractView import AbstractView

class TestViews(object):
    def testAbstractView(self):
        view = AbstractView()

        assert view.document is None
