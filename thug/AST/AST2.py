#!/usr/bin/env python
#
# AST2.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import v8py
import six
import logging
import unittest

from Target import TARGET

log = logging.getLogger("Thug")


class AST(object):
    # Breakpoints
    ASSIGN_BREAKPOINT = 0x00
    LOOP_BREAKPOINT   = 0x01

    # Assignment perators
    OP_ASSIGN         = '='
    OP_ASSIGN_ADD     = '+='
    OP_ASSIGN_SUB     = '-='
    OP_ASSIGN_MUL     = '*='
    OP_ASSIGN_DIV     = '/='
    OP_ASSIGN_MOD     = '%='
    OP_ASSIGN_SHL     = '<<='
    OP_ASSIGN_SAR     = '>>='
    OP_ASSIGN_SHR     = '>>>='
    OP_ASSIGN_BIT_OR  = '|='
    OP_ASSIGN_BIT_XOR = '^='
    OP_ASSIGN_BIT_AND = '&='

    ASSIGN_OPERATORS = (OP_ASSIGN,
                        OP_ASSIGN_ADD,
                        OP_ASSIGN_SUB,
                        OP_ASSIGN_MUL,
                        OP_ASSIGN_DIV,
                        OP_ASSIGN_MOD,
                        OP_ASSIGN_SHL,
                        OP_ASSIGN_SAR,
                        OP_ASSIGN_SHR,
                        OP_ASSIGN_BIT_OR,
                        OP_ASSIGN_BIT_XOR,
                        OP_ASSIGN_BIT_AND,
                        )

    def __init__(self, script, window = None):
        self.names           = list()
        self.assignments     = list()
        self.breakpoints     = list()
        self.calls           = set()
        self.shellcodes      = set()
        self.window          = window
        self.context         = v8py.Context()

        self.__init_esprima()
        self.__init_ast(script)
        self.walk()

    def __init_esprima(self):
        with open('esprima.js', 'r') as fd:
            esprima = fd.read()

        self.context.eval(esprima)

    def __init_ast(self, script):
        target   = TARGET % (script, )
        self.ast = self.context.eval(target)

        self.context.eval('delete esprima')

    def walk(self, body = None, scope = None):
        if body is None:
            body = self.ast.body

        for item in body:
            self._walk(item, scope)

    def _walk(self, item, scope):
            # print("[WALK] {}".format(item.type))
            handler = getattr(self, "on{}".format(item.type), None)
            if handler:
                handler(item, scope)

    def set_breakpoint(self, stmt, scope, _type):
        bp = {
            'type'  : _type,
            'line'  : stmt.loc.end['line'],
            'scope' : scope,
        }

        if bp not in self.breakpoints:
            self.breakpoints.append(bp)

    def onExpressionStatement(self, stmt, scope = None):
        # print(stmt.expression.type)

        handler = getattr(self, 'handle{}'.format(stmt.expression.type), None)
        if handler:
            handler(stmt, scope)

    def handleAssignmentExpression(self, stmt, scope):
        if stmt.expression.operator in self.ASSIGN_OPERATORS:
            self._walk(stmt.expression.left, scope)
            self._walk(stmt.expression.right, scope)
            self.set_breakpoint(stmt, scope, self.ASSIGN_BREAKPOINT)

    def checkCallExpression(self, stmt):
        callee = stmt.expression.callee.name
        line   = stmt.loc.end['line']

        if (callee, line) in self.calls:
            return True

        self.calls.add((callee, line))
        return False

    def handleCallExpression(self, stmt, scope):
        if self.checkCallExpression(stmt):
            return

        callee = stmt.expression.callee.name
        arguments = set()

        for p in stmt.expression.arguments:
            # print(dir(p))
            # print(p.type)
            # if p.type in ('BinaryExpression', ):
                # print(dir(p))
                # print(p.left.raw)
                # print(p.operator)
                # print(p.right.raw)
            if p.type in ('Identifier', ):
                # print(p.name)
                for e in self.assignments:
                    # print(e)
                    if e['scope'] in (scope, ) and e['name'] in (p.name, ):
                        arguments.add(e['value'])
            if p.type in ('Literal', ):
                arguments.add(p['value'])

        # print(arguments)

        handler = getattr(self, 'handle_{}'.format(callee), None)
        if handler:
            handler(arguments)

    def onVariableDeclaration(self, item, scope = None):
        for decl in item.declarations:
            if decl.type not in ('VariableDeclarator', ):
                continue

            name = {
                'name'  : decl.id.name,
                'scope' : scope,
            }

            if name not in self.names:
                self.names.append(name)

            init_type = getattr(decl.init, 'type', None)

            # If init_type is None, two possibilities exist for this variable
            # declaration:
            #   1. no initialization (no need to set a breakpoint)
            #   2. literal assignment initialization
            if init_type is None:
                try:
                    name['value'] = decl.init.raw
                    if name not in self.assignments:
                        self.assignments.append(name)
                    self.set_breakpoint(decl, scope, self.ASSIGN_BREAKPOINT)
                except AttributeError:
                    pass
            else:
                # init_type is not None so some kind of initialization is actually
                # taking place. Set a breakpoint (FIXME and do something else?)
                self.set_breakpoint(decl, scope, self.ASSIGN_BREAKPOINT)

    def onFunctionDeclaration(self, decl, scope = 'global'):
        func_name = decl.id.name
        # func_params = [param.name for param in decl.params]
        # print func_params
        self.walk(decl.body.body, scope = func_name)

    def onIfStatement(self, stmt, scope):
        body = getattr(stmt.alternate, 'body', None)
        if body:
            self.walk(body, scope)

        body = getattr(stmt.consequent, 'body', None)
        if body:
            self.walk(body, scope)

    def onForStatement(self, stmt, scope):
        self.set_breakpoint(stmt, scope, self.LOOP_BREAKPOINT)

    def onWhileStatement(self, stmt, scope):
        self.set_breakpoint(stmt, scope, self.LOOP_BREAKPOINT)

    def onDoWhileStatement(self, stmt, scope):
        self.set_breakpoint(stmt, scope, self.LOOP_BREAKPOINT)

    def onForInStatement(self, stmt, scope):
        self.set_breakpoint(stmt, scope, self.LOOP_BREAKPOINT)

    def add_shellcode(self, sc):
        if isinstance(sc, six.integer_types):
            return

        if len(sc) > 32:
            # log.ThugLogging.shellcodes.add(sc)
            self.shellcodes.add(sc)

    def onLiteral(self, litr, scope = None):
        self.add_shellcode(litr.value)

    def onReturnStatement(self, stmt, scope):
        value = getattr(stmt.argument, 'value', None)
        if not value:
            return

        self.add_shellcode(value)

    def handle_eval(self, args):
        for arg in args:
            s = str(arg)

            if len(s) > 64:
                print("[AST] Eval argument length > 64")


class TestAST(unittest.TestCase):
    DEBUG = False

    def debug_info(self, script, ast):
        if not self.DEBUG:
            return

        print(script)
        print(ast.names)
        print(ast.breakpoints)

    def testAssign(self):
        # print("[testAssign]")

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
        # print("[testVariableDeclaration]")

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
        # print("[testFunctionDeclaration]")

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
        # print("[testFunctionReturnLiteral]")

        script = """
            function test1() {
                var test2 = 1;
                return 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd';
            }
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

        assert 'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd' in ast.shellcodes

    def testCall(self):
        # print("[testCall]")

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
        # print("[testCallEval1]")

        script = """
            var a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            eval(a);
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

    def testCallEval2(self):
        # print("[testCallEval2]")

        script = """
            var a = "A" * 1024;
            eval(a);
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

    def testCallEval3(self):
        # print("[testCallEval3]")

        script = """
            eval("A" * 1024);
        """

        ast = AST(script)
        ast.walk()

        self.debug_info(script, ast)

    def testForStatement(self):
        # print("[testForStatement]")

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
        # print("[testWhileStatement]")

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
        # print("[testWhileStatement]")

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


if __name__ == "__main__":
    unittest.main()
