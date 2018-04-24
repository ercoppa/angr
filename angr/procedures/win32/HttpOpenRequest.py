import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.HttpOpenRequest')

class HttpOpenRequestA(angr.SimProcedure):

    def run(self, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: self.ty_ptr(angr.sim_type.SimTypeString()),
            3: self.ty_ptr(angr.sim_type.SimTypeString()),
            4: self.ty_ptr(angr.sim_type.SimTypeString()),
            5: self.ty_ptr(angr.sim_type.SimTypeString()),
            6: angr.sim_type.SimTypeInt(),
            7: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = claripy.BVS('hInternet_HttpOpenRequestA', 32)
        self.state.se.add(ret_expr != 0)

        return ret_expr