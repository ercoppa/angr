import angr
import logging

l = logging.getLogger('angr.procedures.win32.lstrcat')

class lstrcatA(angr.SimProcedure):

    def run(self, dst, src):

        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()),
                               1: self.ty_ptr(angr.sim_type.SimTypeString())}

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeString())

        assert not self.state.se.symbolic(dst)
        assert not self.state.se.symbolic(src)

        strlen = angr.SimProcedures['libc.so.6']['strlen']
        strncpy = angr.SimProcedures['libc.so.6']['strncpy']

        dst_len = self.inline_call(strlen, dst)
        src_len = self.inline_call(strlen, src)

        ret_expr = self.inline_call(strncpy, dst + dst_len.ret_expr, src, src_len.ret_expr+1, src_len=src_len.ret_expr).ret_expr

        return dst