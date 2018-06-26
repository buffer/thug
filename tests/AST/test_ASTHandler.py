from thug.AST.ASTHandler import ASTHandler


class TestASTHandler:
    ast_handler = ASTHandler()

    def test_init(self):
        args = self.ast_handler.args['eval']
        assert not args

    def test_appending_args(self):
        self.ast_handler.handle_eval(['arg1', 'arg2'])
        args = self.ast_handler.args['eval']

        assert 'arg1' in args
        assert 'arg2' in args

    def test_repeating_args(self):
        self.ast_handler.handle_eval(['arg2', 'arg3'])
        args = self.ast_handler.args['eval']

        assert 'arg2' in args
        assert 'arg3' in args

    def test_length(self, caplog):
        caplog.clear()
        arg = ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']
        self.ast_handler.handle_eval(arg)

        assert "[AST]: Eval argument length > 64" in caplog.text

        args = self.ast_handler.args['eval']
        assert arg[0] in args
