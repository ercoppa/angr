import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.HttpQueryInfo')

class HttpQueryInfoA(angr.SimProcedure):

    def run(self, hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: angr.sim_type.SimTypeInt(),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            4: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr