import angr
import logging

l = logging.getLogger('angr.procedures.win32.wsprintf')

class wsprintfA(angr.SimProcedure):

    def run(self, str_buf_ptr, str_format_ptr):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()),
                                1: self.ty_ptr(angr.sim_type.SimTypeString()),}

        self.return_type = angr.sim_type.SimTypeInt()

        res_str = self.state.se.any_str(self.state.memory.load(str_format_ptr, 128)).split('\x00')[0]

        write_str = res_str + '\x00'
        for i in range(len(write_str)):
            self.state.memory.store(str_buf_ptr + i, ord(write_str[i]), 1)

        ret_expr = len(write_str)
        return ret_expr