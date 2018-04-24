import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.InternetCloseHandle')

class InternetCloseHandle(angr.SimProcedure):

    def run(self, hInternet):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr