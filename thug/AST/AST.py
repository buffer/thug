#!/usr/bin/env python
#
# AST.py
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
import PyV8
import traceback

log = logging.getLogger("Thug")


class AST(object):
    (AssignBreakPoint,
     LoopBreakPoint) = range(0, 2)

    AssignOps = [PyV8.AST.Op.ASSIGN,
                 PyV8.AST.Op.ASSIGN_ADD,
                 PyV8.AST.Op.ASSIGN_BIT_AND,
                 PyV8.AST.Op.ASSIGN_BIT_OR,
                 PyV8.AST.Op.ASSIGN_BIT_XOR,
                 PyV8.AST.Op.ASSIGN_DIV,
                 PyV8.AST.Op.ASSIGN_MOD,
                 PyV8.AST.Op.ASSIGN_MUL,
                 PyV8.AST.Op.ASSIGN_SAR,
                 PyV8.AST.Op.ASSIGN_SHL,
                 PyV8.AST.Op.ASSIGN_SHR,
                 PyV8.AST.Op.ASSIGN_SUB,
                 PyV8.AST.Op.INIT_VAR]

    def __init__(self, window, script):
        self.names           = set()
        self.inLoop          = False
        self.inBlock         = True
        self.exitingLoop     = 0
        self.assignStatement = False
        self.breakpoints     = set()
        self.window          = window

        self.walk(script)

    def checkExitingLoop(self, pos):
        if self.exitingLoop > 0:
            self.exitingLoop -= 1
            self.breakpoints.add((self.LoopBreakPoint, pos))

    def walk(self, script):
        self.block_no = 1

        try:
            PyV8.JSEngine().compile(script).visit(self)
        except UnicodeDecodeError:
            enc = log.Encoding.detect(script, safe = True)
            if enc is None:
                return

            PyV8.JSEngine().compile(script.decode(enc['encoding'])).visit(self)
        except:  # pylint:disable=bare-except
            pass

    def onProgram(self, prog):
        for decl in prog.scope.declarations:
            decl.visit(self)

        for stmt in prog.body:
            stmt.visit(self)

    def _enterBlock(self):
        self.inBlock = True

    def _exitBlock(self):
        self.inBlock = False

    def onBlock(self, block):
        self._enterBlock()
        for stmt in block.statements:
            stmt.visit(self)

        self._exitBlock()
        self.block_no += 1

    def onExpressionStatement(self, stmt):
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

    def onVariableDeclaration(self, decl):
        var = decl.proxy

        if decl.scope.isGlobal:
            getattr(self.window, var.name, None)

        if decl.mode == PyV8.AST.VarMode.var:
            self.names.add(var.name)

    def onFunctionDeclaration(self, decl):
        f = decl.proxy

        if decl.scope.isGlobal:
            getattr(self.window, f.name, None)

        for d in decl.scope.declarations:
            if not getattr(d, 'function', None):
                continue

            d.function.visit(self)

            # for stmt in d.function.body:
            #    stmt.visit(self)

    def onAssignment(self, expr):
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

    def onForStatement(self, stmt):
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

    def onWhileStatement(self, stmt):
        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def onDoWhileStatement(self, stmt):
        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def onForInStatement(self, stmt):
        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.enumerable.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def handle_eval(self, args):
        for arg in args:
            if len(str(arg)) > 64:
                log.warning("[AST]: Eval argument length > 64")

    def onCall(self, expr):
        for arg in expr.args:
            arg.visit(self)

        handle = getattr(self, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        expr.expression.visit(self)

    def onCallNew(self, expr):
        handle = getattr(self, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        for arg in expr.args:
            arg.visit(self)

    def onCallRuntime(self, expr):
        for arg in expr.args:
            arg.visit(self)

    def onFunctionLiteral(self, litr):
        for decl in litr.scope.declarations:
            decl.visit(self)

        for e in litr.body:
            e.visit(self)

    def onLiteral(self, litr):
        if len(str(litr)) > 256:
            log.ThugLogging.shellcodes.add(str(litr).lstrip('"').rstrip('"'))

    def onReturnStatement(self, stmt):
        stmt.expression.visit(self)

    def onCompareOperation(self, stmt):
        stmt.left.visit(self)
        stmt.right.visit(self)

    def onCountOperation(self, stmt):
        stmt.expression.visit(self)
