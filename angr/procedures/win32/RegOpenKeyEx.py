import angr
import logging

l = logging.getLogger('angr.procedures.win32.RegOpenKeyEx')

class RegOpenKeyExA(angr.SimProcedure):

    def run(self, hKey, lpSubKey, ulOptions, samDesired, phkResult):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeLong()

        ret_expr = 0x0 # ERROR_SUCCESS
        return ret_expr