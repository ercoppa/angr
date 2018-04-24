import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.GetLogicalDrives')

class GetLogicalDrives(angr.SimProcedure):

    def run(self, ):

        self.argument_types = {}
        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x4 # only C drive
        return ret_expr