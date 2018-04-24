import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.CreateMutex')

class CreateMutexA(angr.SimProcedure):

    def run(self, lpMutexAttributes, bInitialOwner, lpName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: angr.sim_type.SimTypeInt(),
            2: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = claripy.BVS('CreateMutex_retval', 32)
        self.state.se.add(ret_expr != 0)

        return ret_expr
