import angr
import logging

l = logging.getLogger('angr.procedures.win32.GetSystemDirectory')

class GetSystemDirectoryA(angr.SimProcedure):

    def run(self, str_buf_ptr, str_buf_size):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()),
                                1: angr.sim_type.SimTypeLength(self.state.arch)}

        self.return_type = angr.sim_type.SimTypeLength(self.state.arch)

        assert not self.state.se.symbolic(str_buf_ptr)
        assert not self.state.se.symbolic(str_buf_size)

        system_dir = 'C:\WINDOWS\system32' + chr(0)
        written_size = len(system_dir) - 1

        for i in range(written_size + 1):
            self.state.memory.store(str_buf_ptr + i, ord(system_dir[i]), 1)

        return written_size