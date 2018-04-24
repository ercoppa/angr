import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.HttpSendRequest')

class HttpSendRequestA(angr.SimProcedure):

    def run(self, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: angr.sim_type.SimTypeInt(),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = claripy.BVS('HttpSendRequestA_retval', 32)
        self.state.se.add(ret_expr != 0)

        return ret_expr