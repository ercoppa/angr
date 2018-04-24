import angr
import logging

l = logging.getLogger('angr.procedures.win32.RegSetValueEx')

class RegSetValueExA(angr.SimProcedure):

    def run(self, hKey, lpValueName, Reserved, dwType, lpData, cbData):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: angr.sim_type.SimTypeInt(),
            3: angr.sim_type.SimTypeInt(),
            4: angr.sim_type.SimTypeChar(),
            5: angr.sim_type.SimTypeInt(),
            }

        self.return_type = angr.sim_type.SimTypeLong()

        ret_expr = 0x0 # ERROR_SUCCESS
        return ret_expr