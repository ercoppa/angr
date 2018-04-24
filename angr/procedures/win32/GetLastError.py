import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.GetLastError')

class GetLastError(angr.SimProcedure):

    def run(self):

        self.argument_types = {}

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = claripy.BVS('thread_last_error', 32)
        return ret_expr