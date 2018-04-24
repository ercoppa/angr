import angr
import logging

l = logging.getLogger('angr.procedures.win32.MoveFileA')

class MoveFileA(angr.SimProcedure):

    def run(self, lpExistingFileName, lpNewFileName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr