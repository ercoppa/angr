import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.InternetReadFile')

class InternetReadFile(angr.SimProcedure):

    def run(self, hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(dwNumberOfBytesToRead)
        max_size = self.state.se.max_int(dwNumberOfBytesToRead)

        # make buffer symbolic
        buf = claripy.BVS('InternetReadFile_buffer', 8 * max_size)
        last_b = buf.get_byte(max_size - 1)
        self.state.se.add(last_b == 0x0)
        self.state.memory.store(lpBuffer, buf, max_size)

        assert not self.state.se.symbolic(lpdwNumberOfBytesRead)
        n_written = self.state.se.any_int(lpdwNumberOfBytesRead)
        nw = claripy.BVS('InternetReadFile_buffer_written', 32)
        self.state.se.add(nw <= max_size)
        self.state.memory.store(n_written, claripy.Reverse(nw))

        ret_expr = 0x1
        return ret_expr