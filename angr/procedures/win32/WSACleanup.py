import angr
import logging

l = logging.getLogger('angr.procedures.win32.WSACleanup')

class WSACleanup(angr.SimProcedure):

    def run(self):
        self.argument_types = {}
        self.return_type = angr.sim_type.SimTypeInt()  # actually it is void...

        ret_expr = 0x0
        return ret_expr