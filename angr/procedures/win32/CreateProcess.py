import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.CreateProcess')

class CreateProcessA(angr.SimProcedure):

    def run(self, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: angr.sim_type.SimTypeInt(),
            5: angr.sim_type.SimTypeInt(),
            6: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            7: self.ty_ptr(angr.sim_type.SimTypeString()),
            8: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            9: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1
        return ret_expr