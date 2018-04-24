import angr
import logging

l = logging.getLogger('angr.procedures.win32.WinExec')

class WinExec(angr.SimProcedure):

    def run(self, lpCmdLine, uCmdShow):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: angr.sim_type.SimTypeInt(),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 32  # success
        return ret_expr