import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.FindFirstFile')

class FindFirstFileA(angr.SimProcedure):

    def run(self, lpFileName, lpFindFileData):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        self.state.memory.store(lpFindFileData, claripy.BVS('WIN32_FIND_DATA', 8 * 320))

        ret_expr = claripy.BVS('handle_first_file', 32)
        return ret_expr