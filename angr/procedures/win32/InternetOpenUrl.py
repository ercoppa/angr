import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.InternetOpenUrl')

class InternetOpenUrlA(angr.SimProcedure):

    def run(self, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()),
                                1: angr.sim_type.SimTypeInt(),
                                2: self.ty_ptr(angr.sim_type.SimTypeString()),
                                3: self.ty_ptr(angr.sim_type.SimTypeString()),
                                4: angr.sim_type.SimTypeInt() }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = claripy.BVS('hInternet_url', 32)
        self.state.se.add(ret_expr != 0)

        return ret_expr
