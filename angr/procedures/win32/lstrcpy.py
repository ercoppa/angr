import angr
import logging

l = logging.getLogger('angr.procedures.win32.lstrcpy')

class lstrcpyA(angr.SimProcedure):

    def run(self, dst, src):

        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()),
                               1: self.ty_ptr(angr.sim_type.SimTypeString())}

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeString())

        strlen = angr.SimProcedures['libc.so.6']['strlen']
        strncpy = angr.SimProcedures['libc.so.6']['strncpy']
        src_len = self.inline_call(strlen, src)

        ret_expr = self.inline_call(strncpy, dst, src, src_len.ret_expr+1, src_len=src_len.ret_expr).ret_expr

        return ret_expr