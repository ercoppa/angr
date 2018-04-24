import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.InternetConnect')

class InternetConnectA(angr.SimProcedure):

    def run(self, hInternet, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                                1: self.ty_ptr(angr.sim_type.SimTypeString()),
                                2: angr.sim_type.SimTypeShort(),
                                3: self.ty_ptr(angr.sim_type.SimTypeString()),
                                4: self.ty_ptr(angr.sim_type.SimTypeString()),
                                5: angr.sim_type.SimTypeInt(),
                                6: angr.sim_type.SimTypeInt(),
                                7: self.ty_ptr(angr.sim_type.SimTypeInt()) }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = claripy.BVS('hInternet_connect', 32)
        self.state.se.add(ret_expr != 0)

        return ret_expr