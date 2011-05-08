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

import PyV8

class AST(object):
    def __init__(self, script):
        self.prog  = None
        self.names = set()
        self.walk(script)

    def walk(self, script):
        self.block_no = 1
        with PyV8.JSContext() as ctxt:
            PyV8.JSEngine().compile(script).visit(self)

    def onProgram(self, prog):
        print "[onProgram]"
        print dir(prog)
        print "Program startPos:  %d" % (prog.startPos, )
        print "Program endPos:    %d" % (prog.endPos, )
        for decl in prog.scope.declarations:
            decl.visit(self)

        for stmt in prog.body:
            stmt.visit(self)

    def onBlock(self, block):
        print "[*************] Entering Block #%d [*************]" % (self.block_no, )
        for stmt in block.statements:
            stmt.visit(self)
        print "[*************] Exiting Block  #%d [*************]" % (self.block_no, )
        self.block_no += 1

    def onExpressionStatement(self, stmt):
        print "Statement:         %s" % (stmt, )
        print "Statement type:    %s" % (stmt.type, )
        #print "Expression type:   %s" % (stmt.expression.type, )
        #print "Expression pos:    %s" % (stmt.pos, )
        stmt.expression.visit(self)

    def onDeclaration(self, decl):
        var = decl.proxy
         
        if decl.mode == PyV8.AST.VarMode.var and not decl.function:
            print "Variable Decl:     %s" % (var.name, )
            self.names.add(var.name)
        if decl.function:
            decl.function.visit(self)

    def onAssignment(self, expr):
        print "Assignment Op:     %s" % (expr.op, )
        print "Assignment Pos:    %s" % (expr.pos, )
        print "Assignment Target: %s" % (expr.target, )
        print "Assignment Value:  %s" % (expr.value, )
        self.names.add(str(expr.target))
        expr.target.visit(self)
        expr.value.visit(self)

    def onIfStatement(self, stmt):
        print "[*] If Statement"
        print "If condition:      %s" % (stmt.condition, )
        print "If position:       %s" % (stmt.pos, )
        stmt.condition.visit(self)
        if stmt.hasThenStatement:
            stmt.thenStatement.visit(self)
        if stmt.hasElseStatement:
            stmt.elseStatement.visit(self)

    def onForStatement(self, stmt):
        print "[*] For Statement"
        print "Init condition:    %s" % (stmt.init, )
        print "Next condition:    %s" % (stmt.next, )
        print "End condition:     %s" % (stmt.condition, )
        print "For position:      %s" % (stmt.pos)
        stmt.init.visit(self)
        stmt.next.visit(self)
        stmt.condition.visit(self)
        stmt.body.visit(self)

    def onWhileStatement(self, stmt):
        print "[*] While Statement"
        print "While position:    %s" % (stmt.pos)
        stmt.condition.visit(self)
        stmt.body.visit(self)

    def onDoWhileStatement(self, stmt):
        print "[*] Do-While Statement"
        print "Do-While position: %s" % (stmt.pos)
        stmt.condition.visit(self)
        stmt.body.visit(self)

    def onForInStatement(self, stmt):
        print "[*] For-In Statement"
        print "For-In position:   %s" % (stmt.pos)
        stmt.enumerable.visit(self)
        stmt.body.visit(self)

    def handle_eval(self, args):
        for arg in args:
            #print arg
            if len(str(arg)) > 64:
                print "[WARNING]: Eval argument length > 64"

    def onCall(self, expr):
        print "[*] Call"
        print "[*] Call position: %s" % (expr.pos)
        print "[*] Call expr:     %s" % (expr.expression, )
        #print "[*] Call loopcond: %s" % (expr.loopCondition, )
    
        handle = getattr(self, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        expr.expression.visit(self)

        for arg in expr.args:
            arg.visit(self)

    def onCallNew(self, expr):
        print "[*] CallNew"
        print "[*] Call position: %s" % (expr.pos)
        print "[*] Call expr:     %s" % (expr.expression, )
        #print "[*] Call loopcond: %s" % (expr.loopCondition, )

        handle = getattr(self, "handle_%s" % (expr.expression, ), None)
        if handle:
            handle(expr.args)

        for arg in expr.args:
            arg.visit(self)

    def onCallRuntime(self, expr):
        print "[*] CallRuntime"

        for arg in expr.args:
            arg.visit(self)

    def onFunctionLiteral(self, litr):
        print "Function Literal:  %s" % (litr.name, )
        for decl in litr.scope.declarations:
            decl.visit(self)
        
        for e in litr.body:
            e.visit(self)

    def onLiteral(self, litr):
        print "Literal:           %s" % (litr, )

    def onReturnStatement(self, stmt):
        print "[*] Return Statement"
        print "Return position:   %s" % (stmt.pos)
        stmt.expression.visit(self)

    def onCompareOperation(self, stmt):
        print "Compare Left:      %s" % (stmt.left, )
        stmt.left.visit(self)
        print "Compare Operation: %s" % (stmt.op, )
        print "Compare Right:     %s" % (stmt.right, )
        stmt.right.visit(self)
        #print "Loop Condition:    %s" % (stmt.loopCondition, )

    def onCountOperation(self, stmt):
        print "Count Operation:   %s" % (stmt.op, )
        #print "Count Increment:   %s" % (stmt.increment, )
        #print "Loop Condition:    %s" % (stmt.loopCondition, )
        stmt.expression.visit(self)

    def onVariableProxy(self, expr):
        pass
