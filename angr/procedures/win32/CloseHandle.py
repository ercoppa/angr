import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.CloseHandle')

class CloseHandle(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CloseHandle, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, hObject):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr
