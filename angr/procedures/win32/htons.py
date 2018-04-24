import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.htonl')

class htons(angr.SimProcedure):

    def run(self, hostshort):

        self.argument_types = { 0: angr.sim_type.SimTypeShort() }

        self.return_type = angr.sim_type.SimTypeShort()

        # win32 should be little endian
        ret_expr = claripy.Reverse(hostshort)

        return ret_expr

class ntohs(htons):
    pass