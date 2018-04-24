import angr
import logging

l = logging.getLogger('angr.procedures.win32.RegCloseKey')

class RegCloseKey(angr.SimProcedure):

    def run(self, hKey):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeLong()

        ret_expr = 0x0 # ERROR_SUCCESS
        return ret_expr