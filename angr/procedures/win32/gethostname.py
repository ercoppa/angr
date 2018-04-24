import angr
import logging

l = logging.getLogger('angr.procedures.win32.gethostname')

class gethostname(angr.SimProcedure):

    def run(self, name, namelen):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()),
                                1: angr.sim_type.SimTypeLength(self.state.arch)}

        self.return_type = angr.sim_type.SimTypeInt()

        host_name = '$machine_host_name' + chr(0)
        written_size = len(host_name) - 1

        for i in range(written_size + 1):
            self.state.memory.store(name + i, ord(host_name[i]), 1)

        ret_expr = 0x0

        return ret_expr