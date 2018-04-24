import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.ReadFile')

class ReadFile(angr.SimProcedure):

    def run(self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
        }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(nNumberOfBytesToRead)
        max_size = self.state.se.any_int(nNumberOfBytesToRead)

        buf = claripy.BVS('ReadFile_buffer', 8 * max_size)
        self.state.memory.store(lpBuffer, buf)

        assert not self.state.se.symbolic(lpNumberOfBytesRead)
        ptr = self.state.se.any_int(lpNumberOfBytesRead)

        if ptr != 0:
            b_read = claripy.BVS('ReadFile_bytes_written', 32)
            self.state.se.add(b_read <= max_size)
            self.state.se.add(b_read > 0)
            self.state.memory.store(lpNumberOfBytesRead, claripy.Reverse(b_read))

        ret_expr = 0x1  # SUCCESS
        return ret_expr