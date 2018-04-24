import angr
import logging

l = logging.getLogger('angr.procedures.win32.inet_ntoa')

class inet_ntoa(angr.SimProcedure):

    def run(self, addr):

        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)), }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeString())

        addr = 0xABCDE124
        ip_addr = "192.168.1.1" + '\x00'

        for i in range(len(ip_addr)):
            self.state.memory.store(addr + i, ord(ip_addr[i]), 1)

        ret_expr = addr
        return ret_expr