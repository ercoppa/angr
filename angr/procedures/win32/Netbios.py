import angr
import logging

l = logging.getLogger('angr.procedures.win32.Netbios')

class Netbios(angr.SimProcedure):

    def run(self, pcnb):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))}

        self.return_type = angr.sim_type.SimTypeInt()
        ret_expr = claripy.BVS('Netbios_retval', 32)

        return ret_expr
