import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.CreateFile')

class CreateFileA(angr.SimProcedure):

    def run(self, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: angr.sim_type.SimTypeInt(),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: angr.sim_type.SimTypeInt(),
            5: angr.sim_type.SimTypeInt(),
            6: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = claripy.BVS('handle_file', 32)
        self.state.se.add(ret_expr != 0) # not NULL
        self.state.se.add(ret_expr != 0xFFFFFFFF) # not INVALID_HANDLE_VALUE

        return ret_expr