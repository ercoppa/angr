import angr
import logging

l = logging.getLogger('angr.procedures.win32.GetVersionEx')

class GetVersionExA(angr.SimProcedure):

    def run(self, lpVersionInfo):
        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)), }

        self.return_type = angr.sim_type.SimTypeInt()

        # Windows XP
        self.state.memory.store(lpVersionInfo + 4, 0x5, 4)
        self.state.memory.store(lpVersionInfo + 8, 0x5, 4)
        self.state.memory.store(lpVersionInfo + 16, 0x2, 4)

        ret_expr = 0x1
        return ret_expr