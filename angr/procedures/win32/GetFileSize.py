import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.GetFileSize')

class GetFileSize(angr.SimProcedure):

    def run(self, hFile, lpFileSizeHigh):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = claripy.BVS('file_size', 32)
        self.state.se.add(ret_expr > 0)
        self.state.se.add(ret_expr < 0x100)

        return ret_expr