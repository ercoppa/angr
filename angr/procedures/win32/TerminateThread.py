import angr
import logging

l = logging.getLogger('angr.procedures.win32.TerminateThread')

class TerminateThread(angr.SimProcedure):

    def run(self, hThread, dwExitCode):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: angr.sim_type.SimTypeInt(),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr