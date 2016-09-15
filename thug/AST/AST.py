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
        self.debug(self.breakpoints)
        self.debug(self.names)

    def debug(self, msg):
        if log.ThugOpts.ast_debug:
            log.debug(msg)

    def checkExitingLoop(self, pos):
        if self.exitingLoop > 0:
            self.debug("\tExiting Loop:       %d" % (self.exitingLoop, ))
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
        except: #pylint:disable=bare-except
            pass

    def onProgram(self, prog):
        self.json = prog.toJSON()
        self.ast  = prog.toAST()

        self.debug(self.json)

        self.debug("[*] Program")
        self.debug("\tProgram startPos:   %d" % (prog.startPos, ))
        self.debug("\tProgram endPos:     %d" % (prog.endPos, ))

        for decl in prog.scope.declarations:
            decl.visit(self)

        for stmt in prog.body:
            stmt.visit(self)

    def _enterBlock(self):
        self.inBlock = True

    def _exitBlock(self):
        self.inBlock = False

    def onBlock(self, block):
        self.debug("[*] Entering Block #%d" % (self.block_no, ))
        
        self._enterBlock()
        for stmt in block.statements:
            stmt.visit(self)
        
        self._exitBlock()
        self.debug("[*] Exiting Block  #%d" % (self.block_no, ))
        self.block_no += 1

    def onExpressionStatement(self, stmt):
        self.debug("[*] Expression Statement")
        self.debug("\tStatement:          %s" % (stmt, ))
        self.debug("\tStatement type:     %s" % (stmt.type, ))
        self.debug("\tStatement position: %s" % (stmt.expression.pos, ))

        self.checkExitingLoop(stmt.expression.pos)
        stmt.expression.visit(self)
        if self.assignStatement:
            if self.inBlock:
                # FIXME
                # AstCallRuntime has no 'pos' attribute
                try:
                    pos = stmt.expression.pos
                except: #pylint:disable=bare-except
                    traceback.print_exc()
                    return
            else:
                pos = stmt.expression.pos
                
            self.breakpoints.add((self.AssignBreakPoint, pos))
            self.assignStatement = False

    def onVariableDeclaration(self, decl):
        var = decl.proxy
        self.debug("[*] Variable Declaration Statement")
        self.debug("\tVariable name:        %s" % (var.name, ))

        if decl.scope.isGlobal:
            getattr(self.window, var.name, None)

        if decl.mode == PyV8.AST.VarMode.var:
            self.names.add(var.name)

    def onFunctionDeclaration(self, decl):
        f = decl.proxy
        self.debug("[*] Function Declaration Statement")
        self.debug("\tFunction name:      %s" % (f.name, ))

        if decl.scope.isGlobal:
            getattr(self.window, f.name, None)

        for d in decl.scope.declarations:
            if not getattr(d, 'function', None):
                continue

            d.function.visit(self)

            #for stmt in d.function.body:
            #    stmt.visit(self)

    def onAssignment(self, expr):
        self.debug("[*] Assignment Statement")
        self.debug("\tAssignment op:      %s" % (expr.op, ))
        self.debug("\tAssignment pos:     %s" % (expr.pos, ))
        self.debug("\tAssignment target:  %s" % (expr.target, ))
        self.debug("\tAssignment value:   %s" % (expr.value, ))
        
        if not self.inLoop:
            if expr.op in self.AssignOps:
                self.assignStatement = True
            
        self.names.add(str(expr.target))
        expr.target.visit(self)
        expr.value.visit(self)

    def onIfStatement(self, stmt):
        self.debug("[*] If Statement")
        self.debug("\tIf condition:       %s" % (stmt.condition, ))
        self.debug("\tIf position:        %s" % (stmt.pos, ))

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
        self.debug("[*] For Statement")
        self.debug("\tInit condition:     %s" % (stmt.init, ))
        self.debug("\tNext condition:     %s" % (stmt.nextStmt, ))
        self.debug("\tEnd condition:      %s" % (stmt.condition, ))
        self.debug("\tFor position:       %s" % (stmt.pos))

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
        self.debug("[*] While Statement")
        self.debug("\tWhile position:     %s" % (stmt.pos,))

        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def onDoWhileStatement(self, stmt):
        self.debug("[*] Do-While Statement")
        self.debug("\tDo-While position:  %s" % (stmt.pos,))

        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def onForInStatement(self, stmt):
        self.debug("[*] For-In Statement")
        self.debug("\tFor-In position:    %s" % (stmt.pos,))

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
        self.debug("[*] Call")
        self.debug("\tCall position:  %s" % (expr.pos, ))
        self.debug("\tCall expr:      %s" % (expr.expression, ))
        self.debug("\tCall arguments")

        for arg in expr.args:
            arg.visit(self)

        handle = getattr(self, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        expr.expression.visit(self)

    def onCallNew(self, expr):
        self.debug("[*] CallNew")
        self.debug("\tCall position:  %s" % (expr.pos, ))
        self.debug("\tCall expr:      %s" % (expr.expression, ))

        handle = getattr(self, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        for arg in expr.args:
            arg.visit(self)

    def onCallRuntime(self, expr):
        self.debug("[*] CallRuntime")
        self.debug("\tCall name:          %s" % (expr.name, ))
        
        for arg in expr.args:
            arg.visit(self)

    def onFunctionLiteral(self, litr):
        self.debug("\tFunction Literal:   %s" % (litr.name, ))
        
        for decl in litr.scope.declarations:
            decl.visit(self)
        
        for e in litr.body:
            e.visit(self)

    def onLiteral(self, litr):
        if len(str(litr)) > 256:
            log.ThugLogging.shellcodes.add(str(litr).lstrip('"').rstrip('"'))

        self.debug("\tLiteral:            %s" % (litr, ))

    def onReturnStatement(self, stmt):
        self.debug("[*] Return Statement")
        self.debug("\tReturn position:    %s" % (stmt.pos, ))
        
        stmt.expression.visit(self)

    def onCompareOperation(self, stmt):
        self.debug("[*] Compare Operation")
        self.debug("\tCompare Left:       %s" % (stmt.left, ))
        self.debug("\tCompare Operation:  %s" % (stmt.op, ))
        self.debug("\tCompare Right:      %s" % (stmt.right, ))
        
        stmt.left.visit(self)
        stmt.right.visit(self)

    def onCountOperation(self, stmt):
        self.debug("[*] Count Operation:    %s" % (stmt.op, ))
        stmt.expression.visit(self)

    def onVariableProxy(self, expr):
        self.debug("\tVariable:       %s" % (expr, ))
