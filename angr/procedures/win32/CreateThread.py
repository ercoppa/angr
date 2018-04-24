import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.CreateThread')

class CreateThread(angr.SimProcedure):

    def run(self, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: angr.sim_type.SimTypeLength(),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: angr.sim_type.SimTypeInt(),
            5: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = claripy.BVS('handle_thread', 32)
        self.state.se.add(ret_expr != 0)

        assert not self.state.se.symbolic(lpStartAddress)
        code_addr = self.state.se.any_int(lpStartAddress)

        # sequential approach
        ret_addr = self.state.stack_pop() # remove ret addr
        global verbose

        self.state.regs.esp += 4 * 6 # remove args
        new_state = self.state.copy()
        new_state.stack_push(lpParameter)
        new_state.stack_push(ret_addr) # return to caller

        self.successors.add_successor(new_state, code_addr, new_state.se.true, 'Ijk_Call')
        self.returns = False

        return ret_expr
