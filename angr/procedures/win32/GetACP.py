import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.GetACP')

class GetACP(angr.SimProcedure):

    def run(self):
        self.argument_types = {}

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = claripy.BVV(1252, 32)
        return ret_expr