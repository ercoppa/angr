import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.InternetOpenA')

class InternetOpenA(angr.SimProcedure):

    def run(self, lpszAgent, dwAccessType, lpszProxyName, lpszProxyBypass, dwFlags):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()),
                                1: angr.sim_type.SimTypeInt(),
                                2: self.ty_ptr(angr.sim_type.SimTypeString()),
                                3: self.ty_ptr(angr.sim_type.SimTypeString()),
                                4: angr.sim_type.SimTypeInt() }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = claripy.BVS('hInternet', 32)
        self.state.se.add(ret_expr != 0)

        return ret_expr