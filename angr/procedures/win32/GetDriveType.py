import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.GetDriveType')

class GetDriveTypeA(angr.SimProcedure):

    def run(self, lpRootPathName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x3
        return ret_expr