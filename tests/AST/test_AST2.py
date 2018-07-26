import logging

from thug.AST.AST2 import AST

log = logging.getLogger("Thug")


class TestAST2(object):
    DEBUG = False

    def debug_info(self, script, ast):
        if not self.DEBUG:
            return

        print(script)
        print(ast.names)
        print(ast.breakpoints)

    def testAssign(self):
        script  = """;
            var number = 0;
            number += 1;
            number -= 1;
            number *= 2;
            number /= 3;
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

        for bp in ast.breakpoints:
            bp_type = bp['type']
            bp_line = bp['line']

            if bp_type in (ast.ASSIGN_BREAKPOINT, ):
                assert bp_line in (2, 3, 4, 5, 6, )

    def testVariableDeclaration(self):
        script  = """
            var uninitialized;
            var foo = "bar";
            var number = 1;
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

        names = [p['name'] for p in ast.names]

        assert 'uninitialized' in names
        assert 'foo' in names
        assert 'number' in names

        for bp in ast.breakpoints:
            bp_type = bp['type']
            bp_line = bp['line']

            if bp_type in (ast.ASSIGN_BREAKPOINT, ):
                assert bp_line in (3, 4, )

    def testFunctionDeclaration(self):
        script = """
            function foo(bar) {
                var a;
                a = "qwerty";
                return a;
            }
        """
        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

        assert {'name': 'a', 'scope': 'foo'} in ast.names
        assert {'scope': 'foo', 'line': 4, 'type': ast.ASSIGN_BREAKPOINT} in ast.breakpoints

    def testFunctionReturnLiteral(self):
        script = """
            function test1() {
                var test2 = 1;
                return 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd';
            }
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

        assert 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd' in log.ThugLogging.shellcodes

    def testCall(self):
        script = """
            function callme(a) {
                return a;
            }

            callme('foobar');
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

    def testCallEval1(self):
        script = """
            var a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            eval(a);
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

    def testCallEval2(self):
        script = """
            var a = "A" * 1024;
            eval(a);
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

    def testCallEval3(self):
        script = """
            eval("A" * 1024);
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

    def testForStatement(self):
        script = """
            var s;
            var i = 0;

            for (i = 0; i < 3; i++) {
                 s += "a";
            }
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

        for bp in ast.breakpoints:
            bp_type = bp['type']
            bp_line = bp['line']

            if bp_type in (ast.LOOP_BREAKPOINT, ):
                assert bp_line in (7, )
            if bp_type in (ast.ASSIGN_BREAKPOINT, ):
                assert bp_line in (3, )

    def testWhileStatement(self):
        script = """
            var s;
            var i = 3;

            while (i > 0) {
                s += "a";
                i -= 1;
            }
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

        for bp in ast.breakpoints:
            bp_type = bp['type']
            bp_line = bp['line']

            if bp_type in (ast.LOOP_BREAKPOINT, ):
                assert bp_line in (8, )
            if bp_type in (ast.ASSIGN_BREAKPOINT, ):
                assert bp_line in (3, )

    def testIfStatement(self):
        script = """
            var s;
            var i = 3;

            if (i > 4) {
                while (i > 0) {
                    s += "a";
                    i -= 1;
                }
            }
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

        for bp in ast.breakpoints:
            bp_type = bp['type']
            bp_line = bp['line']

            if bp_type in (ast.LOOP_BREAKPOINT, ):
                assert bp_line in (9, )
            if bp_type in (ast.ASSIGN_BREAKPOINT, ):
                assert bp_line in (3, )
