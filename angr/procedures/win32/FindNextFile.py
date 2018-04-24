import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.FindNextFile')

class FindNextFileA(angr.SimProcedure):

    def run(self, hFindFile, lpFindFileData):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        # no more file to search...
        ret_expr = 0x0
        return ret_expr