import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.CreateDirectory')

class CreateDirectoryA(angr.SimProcedure):

    def run(self, lpPathName, lpSecurityAttributes):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr