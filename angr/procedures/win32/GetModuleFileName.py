import angr
import logging

l = logging.getLogger('angr.procedures.win32.GetModuleFileName')

class GetModuleFileNameA(angr.SimProcedure):

    def run(self, hModule, lpFilename, nSize):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                                1: self.ty_ptr(angr.sim_type.SimTypeString()),
                                2: angr.sim_type.SimTypeInt() }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(hModule)
        if self.state.se.any_int(hModule) == 0x0:
            res_str = "C:\\$path_to_binary" + '\x00'
        else:
            assert False # ToDo: not yet implemented

        for i in range(len(res_str)):
            self.state.memory.store(lpFilename + i, ord(res_str[i]), 1)

        ret_expr = len(res_str)
        return ret_expr