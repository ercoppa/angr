import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.gethostbyname')

class gethostbyname(angr.SimProcedure):

    def run(self, name):
        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()), }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(name)

        name_str = self.state.se.any_str(self.state.memory.load(name, 128)).split('\x00')[0]
        ret_expr = claripy.BVS('gethostbyname_retval', 32)

        return ret_expr