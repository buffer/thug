#!/usr/bin/env python
#
# AST3.py
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
import six
import esprima

log = logging.getLogger("Thug")


class ASTVisitor(esprima.NodeVisitor):
    def __init__(self, ast):
        self.ast    = ast
        self._scope = list()

    @property
    def scope(self):
        return self._scope[-1] if self._scope else 'global'

    def visit_FunctionDeclaration(self, node):
        func_name = node.id.name

        self._scope.append(func_name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_VariableDeclaration(self, node):
        for decl in node.declarations:
            if decl.type not in ('VariableDeclarator', ):
                continue

            self.ast.set_name(self.scope, decl.id.name)

            init = getattr(decl, "init", None)
            if init is None:
                return

            self.ast.set_assign_breakpoint(self.scope, decl)

            raw = getattr(init, "raw", None)
            if raw:
                self.ast.set_assignment(self.scope, decl.id.name, raw)

        self.generic_visit(node)

    def visit_ForStatement(self, node):
        self.ast.set_loop_breakpoint(self.scope, node)

    def visit_WhileStatement(self, node):
        self.ast.set_loop_breakpoint(self.scope, node)

    def visit_DoWhileStatement(self, node):
        self.ast.set_loop_breakpoint(self.scope, node)

    def visit_ForInStatement(self, node):
        self.ast.set_loop_breakpoint(self.scope, node)

    def visit_ReturnStatement(self, node):
        self.ast.add_shellcode(node.argument.value)
        self.generic_visit(node)

    def handle_CallExpression(self, node):
        for p in node.expression.arguments:
            if p.type in ('Literal', ):
                self.ast.add_shellcode(p.value)

    def handle_AssignmentExpression(self, node):
        if node.expression.operator not in self.ast.ASSIGN_OPERATORS:
            return

        self.ast.set_name(self.scope, node.expression.left.name)
        self.ast.set_assign_breakpoint(self.scope, node.expression)

    def visit_ExpressionStatement(self, node):
        _type = node.expression.type
        handler = getattr(self, 'handle_{}'.format(_type), None)
        if handler:
            handler(node)

        self.generic_visit(node)


class AST(object):
    # Breakpoints
    ASSIGN_BREAKPOINT = 0x00
    LOOP_BREAKPOINT   = 0x01

    # Assignment operators
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
        self.names       = list()
        self.assignments = list()
        self.breakpoints = list()
        self.calls       = set()
        self.shellcodes  = set()
        self.visitor     = ASTVisitor(self)
        self.window      = window

        try:
            self.__init_ast(script)
        except Exception:
            if log.ThugOpts.ast_debug:
                log.warning("[AST] Script parsing error (see trace below)")
                log.warning(traceback.format_exc())

    def __init_ast(self, script):
        self.ast = esprima.parse(script, {'loc'      : True,
                                          'tolerant' : True
                                          }, delegate = self.visitor)

    def walk(self):
        self.visitor.visit(self.ast)

    def set_breakpoint(self, scope, node, _type):
        bp = {
            'type'  : _type,
            'line'  : node.loc.end.line,
            'scope' : scope,
        }

        if bp not in self.breakpoints:
            self.breakpoints.append(bp)

    def set_assign_breakpoint(self, scope, node):
        self.set_breakpoint(scope, node, self.ASSIGN_BREAKPOINT)

    def set_loop_breakpoint(self, scope, node):
        self.set_breakpoint(scope, node, self.LOOP_BREAKPOINT)

    def set_name(self, scope, name):
        _name = {
            'name'  : name,
            'scope' : scope
        }

        if _name not in self.names:
            self.names.append(_name)

    def set_assignment(self, scope, name, value):
        _assignment = {
            'name'  : name,
            'scope' : scope,
            'value' : value
        }

        if _assignment not in self.assignments:
            self.assignments.append(_assignment)

    def add_shellcode(self, sc):
        if not isinstance(sc, (six.string_types, six.text_type, six.binary_type)):
            return

        if len(sc) < 32:
            return

        try:
            log.ThugLogging.shellcodes.add(sc.encode('latin1'))
        except Exception:
            self.shellcodes.add(sc)
