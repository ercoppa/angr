import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.HttpEndRequest')

class HttpEndRequestA(angr.SimProcedure):

    def run(self, hRequest, lpBuffersOut, dwFlags, dwContext):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr