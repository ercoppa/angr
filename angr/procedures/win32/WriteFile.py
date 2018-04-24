import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.WriteFile')

class WriteFile(angr.SimProcedure):

    def run(self, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        # up to requested bytes are written
        b_written = claripy.BVS('WriteFile_bytes_written', 32)
        self.state.se.add(b_written <= nNumberOfBytesToWrite)
        self.state.se.add(b_written > 0)
        self.state.memory.store(lpNumberOfBytesWritten, claripy.Reverse(b_written))
        self.state.memory.store(lpNumberOfBytesWritten, claripy.Reverse(nNumberOfBytesToWrite))

        ret_expr = 0x1
        return ret_expr