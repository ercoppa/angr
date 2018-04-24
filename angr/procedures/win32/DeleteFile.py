import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.DeleteFile')

class DeleteFileA(angr.SimProcedure):

    def run(self, lpFileName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr