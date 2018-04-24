import angr
import logging

l = logging.getLogger('angr.procedures.win32.Sleep')

class Sleep(angr.SimProcedure):

    def run(self, dwMilliseconds):

        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x0 # void
        return ret_expr