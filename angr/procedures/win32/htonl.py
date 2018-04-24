import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.htonl')

class htonl(angr.SimProcedure):

    def run(self, hostlong):

        self.argument_types = { 0: angr.sim_type.SimTypeInt() }

        self.return_type = angr.sim_type.SimTypeInt()

        # win32 should be little endian
        ret_expr = claripy.Reverse(hostlong)

        return ret_expr

class ntohl(htonl):
    pass