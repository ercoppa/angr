import angr
import logging

l = logging.getLogger('angr.procedures.win32.WSAStartup')

class WSAStartup(angr.SimProcedure):

    def run(self, wVersionRequested, lpWSAData):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                                1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))}

        self.return_type = angr.sim_type.SimTypeInt()
        ret_expr = 0x0

        return ret_expr