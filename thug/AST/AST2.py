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


import logging
import traceback

from Target import TARGET 

log = logging.getLogger("Thug")


class AST(object):
    (AssignBreakPoint,
     LoopBreakPoint) = range(0, 2)

    def __init__(self, context, script , window = None):
        self.names           = set()
        self.assignStatement = False
        self.breakpoints     = set()
        self.window          = window
        self.context         = context

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

    def walk(self):
        for item in self.ast.body:
            print(item.type)
            handler = getattr(self, "on{}".format(item.type), None)
            if handler:
                handler(item)

    def _onExpressionStatement(self, stmt):
        self.checkExitingLoop(stmt.expression.pos)
        stmt.expression.visit(self)
        if self.assignStatement:
            if self.inBlock:
                # FIXME
                # AstCallRuntime has no 'pos' attribute
                try:
                    pos = stmt.expression.pos
                except:  # pylint:disable=bare-except
                    traceback.print_exc()
                    return
            else:
                pos = stmt.expression.pos

            self.breakpoints.add((self.AssignBreakPoint, pos))
            self.assignStatement = False

    def onVariableDeclaration(self, item):
        for decl in item.declarations:
            if decl.type not in ('VariableDeclarator', ):
                continue

            try:
                raw = decl.init.raw
            except AttributeError:
                # No variable initialization. No need to note it
                continue

            self.names.add(decl.id.name)
            self.breakpoints.add((self.AssignBreakPoint, decl.loc.end['line']))

    def onFunctionDeclaration(self, decl):
        print(decl.body.body[0].type)
        return
        # f = decl.proxy

        # if decl.scope.isGlobal:
        #    getattr(self.window, f.name, None)

        for d in decl.scope.declarations:
            if not getattr(d, 'function', None):
                continue

            d.function.visit(self)

            # for stmt in d.function.body:
            #    stmt.visit(self)

    def _onAssignment(self, expr):
        if not self.inLoop:
            if expr.op in self.AssignOps:
                self.assignStatement = True

        self.names.add(str(expr.target))
        expr.target.visit(self)
        expr.value.visit(self)

    def onIfStatement(self, stmt):
        stmt.condition.visit(self)

        if stmt.hasThenStatement:
            stmt.thenStatement.visit(self)
        if stmt.hasElseStatement:
            stmt.elseStatement.visit(self)

    def enterLoop(self):
        self.inLoop = True

    def exitLoop(self):
        self.inLoop = False
        self.exitingLoop += 1

    def _onForStatement(self, stmt):
        self.checkExitingLoop(stmt.pos)
        self.enterLoop()

        if stmt.init:
            stmt.init.visit(self)

        if stmt.nextStmt:
            stmt.nextStmt.visit(self)

        if stmt.condition:
            stmt.condition.visit(self)

        if stmt.body:
            stmt.body.visit(self)

        self.exitLoop()

    def _onWhileStatement(self, stmt):
        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def _onDoWhileStatement(self, stmt):
        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def _onForInStatement(self, stmt):
        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.enumerable.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def _onCall(self, expr):
        for arg in expr.args:
            arg.visit(self)

        handle = getattr(log.ASTHandler, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        expr.expression.visit(self)

    def _onCallNew(self, expr):
        handle = getattr(log.ASTHandler, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        for arg in expr.args:
            arg.visit(self)

    def _onCallRuntime(self, expr):
        for arg in expr.args:
            arg.visit(self)

    def _onFunctionLiteral(self, litr):
        for decl in litr.scope.declarations:
            decl.visit(self)

        for e in litr.body:
            e.visit(self)

    def _onLiteral(self, litr):
        if len(str(litr)) > 256:
            log.ThugLogging.shellcodes.add(str(litr).lstrip('"').rstrip('"'))

    def _onReturnStatement(self, stmt):
        stmt.expression.visit(self)

    def _onCompareOperation(self, stmt):
        stmt.left.visit(self)
        stmt.right.visit(self)

    def _onCountOperation(self, stmt):
        stmt.expression.visit(self)


import unittest
import v8py


class TestAST(unittest.TestCase):
    def testVariableDeclaration(self):
        context = v8py.Context()

        script  = """
            var uninitialized;
            var foo = "bar";
            var number = 1;
        """

        ast = AST(context, script)
        ast.walk()

        assert 'uninitialized' not in ast.names
        assert 'foo' in ast.names
        assert 'number' in ast.names

        for bp in ast.breakpoints:
            bp_type = bp[0]
            bp_line  = bp[1]

            if bp_type in (ast.AssignBreakPoint, ): 
                assert bp_line in (3, 4, )

    def testFunctionDeclaration(self):
        context = v8py.Context()

        script = """
            function foo(bar) {
                var a;
                a = 1;
                return a;
            }
        """
        ast = AST(context, script)
        ast.walk()

if __name__ == "__main__":
    unittest.main()
