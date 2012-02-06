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
import json

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

    def __init__(self, script):
        self.names           = set()
        self.inLoop          = False
        self.inBlock         = True
        self.exitingLoop     = 0
        self.assignStatement = False
        self.breakpoints     = set()

        self.walk(script)
        log.debug(self.breakpoints)

    def checkExitingLoop(self, pos):
        if self.exitingLoop > 0:
            log.debug("\tExiting Loop:       %d" % (self.exitingLoop, ))
            self.exitingLoop -= 1
            self.breakpoints.add((self.LoopBreakPoint, pos))

    def walk(self, script):
        self.block_no = 1
        with PyV8.JSContext() as ctxt:
            PyV8.JSEngine().compile(script).visit(self)

    def onProgram(self, prog):
        log.debug("[*] Program")
        log.debug("\tProgram startPos:   %d" % (prog.startPos, ))
        log.debug("\tProgram endPos:     %d" % (prog.endPos, ))
       
        self.json = prog.toJSON()
        self.ast  = prog.toAST()

        log.debug(self.json)

        for decl in prog.scope.declarations:
            decl.visit(self)

        for stmt in prog.body:
            stmt.visit(self)

    def _enterBlock(self):
        self.inBlock = True

    def _exitBlock(self):
        self.inBlock = False

    def onBlock(self, block):
        log.debug("[***] Entering Block #%d [***]" % (self.block_no, ))
        
        self._enterBlock()
        for stmt in block.statements:
            stmt.visit(self)
        
        self._exitBlock()
        log.debug("[***] Exiting Block  #%d [***]" % (self.block_no, ))
        self.block_no += 1

    def onExpressionStatement(self, stmt):
        log.debug("[*] Expression Statement")
        log.debug("\tStatement:          %s" % (stmt, ))
        log.debug("\tStatement type:     %s" % (stmt.type, ))
        log.debug("\tStatement position: %s" % (stmt.pos, ))

        self.checkExitingLoop(stmt.pos)
        stmt.expression.visit(self)
        if self.assignStatement:
            if self.inBlock:
                # FIXME
                # AstCallRuntime has no 'pos' attribute
                try:
                    pos = stmt.expression.pos
                except:
                    return
            else:
                pos = stmt.pos
                
            self.breakpoints.add((self.AssignBreakPoint, pos))
            self.assignStatement = False

    def onDeclaration(self, decl):
        var = decl.proxy
        log.debug("[*] Declaration Statement")
        log.debug("\tDeclaration:        %s" % (var.name, ))

        if decl.mode == PyV8.AST.VarMode.var and not decl.function:
            self.names.add(var.name)
        if decl.function:
            decl.function.visit(self)

    def onAssignment(self, expr):
        log.debug("[*] Assignment Statement")
        log.debug("\tAssignment op:      %s" % (expr.op, ))
        log.debug("\tAssignment pos:     %s" % (expr.pos, ))
        log.debug("\tAssignment target:  %s" % (expr.target, ))
        log.debug("\tAssignment value:   %s" % (expr.value, ))
        
        if not self.inLoop:
            if expr.op in self.AssignOps:
                self.assignStatement = True
            
        self.names.add(str(expr.target))
        expr.target.visit(self)
        expr.value.visit(self)

    def onIfStatement(self, stmt):
        log.debug("[*] If Statement")
        log.debug("\tIf condition:       %s" % (stmt.condition, ))
        log.debug("\tIf position:        %s" % (stmt.pos, ))

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
        log.debug("[*] For Statement")
        log.debug("\tInit condition:     %s" % (stmt.init, ))
        log.debug("\tNext condition:     %s" % (stmt.next, ))
        log.debug("\tEnd condition:      %s" % (stmt.condition, ))
        log.debug("\tFor position:       %s" % (stmt.pos))

        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        if stmt.init:
            stmt.init.visit(self)

        if stmt.next:
            stmt.next.visit(self)
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def onWhileStatement(self, stmt):
        log.debug("[*] While Statement")
        log.debug("\tWhile position:     %s" % (stmt.pos,))

        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def onDoWhileStatement(self, stmt):
        log.debug("[*] Do-While Statement")
        log.debug("\tDo-While position:  %s" % (stmt.pos,))

        self.checkExitingLoop(stmt.pos)
        self.enterLoop()
        stmt.condition.visit(self)
        stmt.body.visit(self)
        self.exitLoop()

    def onForInStatement(self, stmt):
        log.debug("[*] For-In Statement")
        log.debug("\tFor-In position:    %s" % (stmt.pos,))

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
        log.debug("[*] Call")
        log.debug("\tCall position:  %s" % (expr.pos, ))
        log.debug("\tCall expr:      %s" % (expr.expression, ))
   
        handle = getattr(self, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        expr.expression.visit(self)

        for arg in expr.args:
            arg.visit(self)

    def onCallNew(self, expr):
        log.debug("[*] CallNew")
        log.debug("\tCall position:  %s" % (expr.pos, ))
        log.debug("\tCall expr:      %s" % (expr.expression, ))

        handle = getattr(self, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        for arg in expr.args:
            arg.visit(self)

    def onCallRuntime(self, expr):
        log.debug("[*] CallRuntime")

        for arg in expr.args:
            arg.visit(self)

    def onFunctionLiteral(self, litr):
        log.debug("\tFunction Literal:   %s" % (litr.name, ))
        
        for decl in litr.scope.declarations:
            decl.visit(self)
        
        for e in litr.body:
            e.visit(self)

    def onLiteral(self, litr):
        log.debug("Literal:            %s" % (litr, ))

    def onReturnStatement(self, stmt):
        log.debug("[*] Return Statement")
        log.debug("\tReturn position:    %s" % (stmt.pos, ))
        
        stmt.expression.visit(self)

    def onCompareOperation(self, stmt):
        log.debug("[*] Compare Operation")
        log.debug("\tCompare Left:       %s" % (stmt.left, ))
        log.debug("\tCompare Operation:  %s" % (stmt.op, ))
        log.debug("\tCompare Right:      %s" % (stmt.right, ))
        
        stmt.left.visit(self)
        stmt.right.visit(self)

    def onCountOperation(self, stmt):
        log.debug("[*] Count Operation:    %s" % (stmt.op, ))
        
        stmt.expression.visit(self)

    def onVariableProxy(self, expr):
        pass
