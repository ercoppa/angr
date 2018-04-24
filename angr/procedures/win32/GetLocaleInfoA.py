import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.GetLocaleInfo')

class GetLocaleInfoA(angr.SimProcedure):

    def run(self, Locale, LCType, lpLCData, cchData):

        self.argument_types = {0: angr.sim_type.SimTypeInt(),
                               1: angr.sim_type.SimTypeInt(),
                               2: self.ty_ptr(angr.sim_type.SimTypeString()),
                               3: angr.sim_type.SimTypeInt()}

        self.return_type = angr.sim_type.SimTypeInt()

        locale_str = "0409" + '\x00'

        for i in range(len(locale_str)):
            self.state.memory.store(lpLCData + i, ord(locale_str[i]), 1)

        ret_expr = claripy.BVV(5, 32)
        return ret_expr