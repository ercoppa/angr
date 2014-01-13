#!/usr/bin/env python

import copy
import itertools

import symexec
import s_memory
import s_arch
import functools
from .s_value import SimValue
from .s_helpers import fix_endian
from s_exception import SimMergeError

import logging
l = logging.getLogger("s_state")

def arch_overrideable(f):
	@functools.wraps(f)
	def wrapped_f(self, *args, **kwargs):
		if hasattr(self.arch, f.__name__):
			arch_f = getattr(self.arch, f.__name__)
			return arch_f(self, *args, **kwargs)
		else:
			return f(self, *args, **kwargs)
	return wrapped_f

default_plugins = { }

# This is a base class for SimState plugins. A SimState plugin will be copied along with the state when the state is branched. They
# are intended to be used for things such as tracking open files, tracking heap details, and providing storage and persistence for SimProcedures.
class SimStatePlugin:
	def __init__(self):
		self.state = None

	# Sets a new state (for example, if it the state has been branched)
	def set_state(self, state):
		self.state = state

	# Should return a copy of the state plugin.
	def copy(self):
		raise Exception("copy() not implement for %s", self.__class__.__name__)

	@staticmethod
	def register_default(name, cls):
		if name in default_plugins:
			raise Exception("%s is already set as the default for %s" % (default_plugins[name], name))
		default_plugins[name] = cls

# This is a counter for the state-merging symbolic variables
merge_counter = itertools.count()

class SimState: # pylint: disable=R0904
	def __init__(self, temps=None, registers=None, memory=None, old_constraints=None, arch="AMD64", memory_backer=None, plugins=None):
		# the architecture is used for function simulations (autorets) and the bitness
		self.arch = s_arch.Architectures[arch] if isinstance(arch, str) else arch

		# VEX temps are temporary variables local to an IRSB
		self.temps = temps if temps is not None else { }

		# VEX treats both memory and registers as memory regions
		if memory:
			self.memory = memory
		else:
			if memory_backer is None: memory_backer = { }
			vectorized_memory = s_memory.Vectorizer(memory_backer)
			self.memory = s_memory.SimMemory(vectorized_memory, memory_id="mem", bits=self.arch.bits)

		if registers:
			self.registers = registers
		else:
			self.registers = s_memory.SimMemory({ }, memory_id="reg", bits=self.arch.bits)

		# let's keep track of the old and new constraints
		self.old_constraints = old_constraints if old_constraints else [ ]
		self.new_constraints = [ ]
		self.branch_constraints = [ ]

		# plugins
		self.plugins = { }
		if plugins is not None:
			for n,p in plugins.iteritems():
				self.register_plugin(n, p)

		self.track_constraints = True

	def get_plugin(self, name):
		if name not in self.plugins:
			p = default_plugins[name]()
			self.register_plugin(name, p)
			return p
		return self.plugins[name]

	def register_plugin(self, name, plugin):
		plugin.set_state(self)
		self.plugins[name] = plugin

	def simplify(self):
		if len(self.old_constraints) > 0:
			self.old_constraints = [ symexec.simplify(symexec.And(*self.old_constraints)) ]

		if len(self.new_constraints) > 0:
			self.new_constraints = [ symexec.simplify(symexec.And(*self.new_constraints)) ]

		if len(self.branch_constraints) > 0:
			self.branch_constraints = [ symexec.simplify(symexec.And(*self.branch_constraints)) ]

	def constraints_after(self):
		return self.old_constraints + self.new_constraints + self.branch_constraints

	def constraints_before(self):
		return copy.copy(self.old_constraints)

	def constraints_avoid(self):
		# if there are no branch constraints, we can't avoid
		if len(self.branch_constraints) == 0:
			return self.old_constraints + [ symexec.BitVecVal(1, 1) == 0 ]
		else:
			return self.old_constraints + [ symexec.Not(symexec.And(*self.branch_constraints)) ]

	def add_constraints(self, *args):
		if self.track_constraints:
			self.new_constraints.extend(args)

	def add_branch_constraints(self, *args):
		if self.track_constraints:
			self.branch_constraints.extend(args)

	def clear_constraints(self):
		self.old_constraints = [ ]
		self.new_constraints = [ ]
		self.branch_constraints = [ ]

	def get_constraints(self, when="after"):
		if when == "after":
			return self.constraints_after()
		elif when == "before":
			return self.constraints_before()
		elif when == "avoid":
			return self.constraints_avoid()

	# Helper function for loading from symbolic memory and tracking constraints
	def simmem_expression(self, simmem, addr, length, when="after"):
		if type(addr) != int and not isinstance(addr, SimValue):
			# it's an expression
			addr = SimValue(addr, self.get_constraints(when=when))

		# do the load and track the constraints
		m,e = simmem.load(addr, length)
		self.add_constraints(*e)
		return m

	# Helper function for storing to symbolic memory and tracking constraints
	def store_simmem_expression(self, simmem, addr, content, when="after"):
		if type(addr) != int and not isinstance(addr, SimValue):
			# it's an expression
			addr = SimValue(addr, self.get_constraints(when=when))

		# do the store and track the constraints
		e = simmem.store(addr, content)
		self.add_constraints(*e)
		return e

	####################################
	### State progression operations ###
	####################################

	# Applies new constraints to the state so that a branch is avoided.
	def inplace_avoid(self):
		self.old_constraints = self.constraints_avoid()
		self.new_constraints = [ ]
		self.branch_constraints = [ ]

	# Applies new constraints to the state so that a branch (if any) is taken
	def inplace_after(self):
		self.old_constraints = self.constraints_after()
		self.new_constraints = [ ]
		self.branch_constraints = [ ]

	##################################
	### State branching operations ###
	##################################

	# Returns a dict that is a copy of all the state's plugins
	def copy_plugins(self):
		return { n: p.copy() for n,p in self.plugins.iteritems() }

	# Copies a state without its constraints
	def copy_unconstrained(self):
		c_temps = copy.copy(self.temps)
		c_mem = self.memory.copy()
		c_registers = self.registers.copy()
		c_constraints = [ ]
		c_arch = self.arch
		c_plugins = self.copy_plugins()
		return SimState(c_temps, c_registers, c_mem, c_constraints, c_arch, c_plugins)

	# Copies a state so that a branch (if any) is taken
	def copy_after(self):
		c = self.copy_unconstrained()
		c.old_constraints = self.constraints_after()
		return c

	# Creates a copy of the state, discarding added constraints
	def copy_before(self):
		c = self.copy_unconstrained()
		c.old_constraints = self.constraints_before()

		return c

	# Copies a state so that a branch is avoided
	def copy_avoid(self):
		c = self.copy_unconstrained()
		c.old_constraints = self.constraints_avoid()
		return c

	# Copies the state, with all the new and branch constraints un-applied but present
	def copy_exact(self):
		c = self.copy_before()
		c.new_constraints = copy.copy(self.new_constraints)
		c.branch_constraints = copy.copy(self.branch_constraints)

	# Merges this state with the other state. Discards temps by default.
	def merge(self, other, keep_temps = False):
		merge_flag = symexec.BitVec("state_merge_%d" % merge_counter.next(), 1)
		merge_us_value = 1

		if self.plugins.keys() != other.plugins.keys():
			raise SimMergeError("Unable to merge due to different sets of plugins.")
		if self.arch != other.arch:
			raise SimMergeError("Unable to merge due to different architectures.")

		# memory and registers
		self.memory.merge(other, merge_flag, merge_us_value)
		self.registers.merge(other, merge_flag, merge_us_value)

		# temps
		if keep_temps:
			raise SimMergeError("Please implement temp merging or bug Yan.")

		# old constraints
		our_o = symexec.And(*self.old_constraints) if len(self.old_constraints) > 0 else True
		their_o = symexec.And(*other.old_constraints) if len(other.old_constraints) > 0 else True
		self.old_constraints = [ symexec.If(merge_flag == merge_us_value, our_o, their_o) ]

		# new constraints
		our_n = symexec.And(*self.new_constraints) if len(self.new_constraints) > 0 else True
		their_n = symexec.And(*other.new_constraints) if len(other.new_constraints) > 0 else True
		self.new_constraints = [ symexec.If(merge_flag == merge_us_value, our_n, their_n) ]

		# branch constraints
		our_b = symexec.And(*self.branch_constraints) if len(self.branch_constraints) > 0 else True
		their_b = symexec.And(*other.branch_constraints) if len(other.branch_constraints) > 0 else True
		self.branch_constraints = [ symexec.If(merge_flag == merge_us_value, our_b, their_b) ]

		# plugins
		for p in self.plugins:
			self.plugins[p].merge(other.plugins[p], merge_flag, merge_us_value)

	#############################################
	### Accessors for tmps, registers, memory ###
	#############################################

	# Returns a SimValue of the expression, with the specified constraint set
	def expr_value(self, expr, extra_constraints=list(), when="after"):
		return SimValue(expr, self.get_constraints(when=when) + extra_constraints)

	# Returns the BitVector expression of a VEX temp value
	def tmp_expr(self, tmp):
		return self.temps[tmp]

	# Returns the SimValue representing a VEX temp value
	def tmp_value(self, tmp, when="after"):
		return self.expr_value(self.tmp_expr(tmp), when=when)

	# Stores a BitVector expression in a VEX temp value
	def store_tmp(self, tmp, content):
		if tmp not in self.temps:
			# Non-symbolic
			self.temps[tmp] = content
		else:
			# Symbolic
			self.add_constraints(self.temps[tmp] == content)

	# Returns the BitVector expression of the content of a register
	def reg_expr(self, offset, length=None, when="after"):
		if length is None: length = self.arch.bits / 8
		return self.simmem_expression(self.registers, offset, length, when)

	# Returns the SimValue representing the content of a register
	def reg_value(self, offset, length=None, when="after"):
		return self.expr_value(self.reg_expr(offset, length, when), when=when)

	# Returns a concretized value of the content in a register
	def reg_concrete(self, *args, **kwargs):
		return symexec.utils.concretize_constant(self.reg_expr(*args, **kwargs))

	# Stores a bitvector expression in a register
	def store_reg(self, offset, content, length=None, when="after"):
		if type(content) == int:
			if not length:
				l.warning("Length not provided to store_reg with integer content. Assuming bit-width of CPU.")
				length = self.arch.bits / 8
			content = symexec.BitVecVal(content, length * 8)
		return self.store_simmem_expression(self.registers, offset, content, when)

	# Returns the BitVector expression of the content of memory at an address
	def mem_expr(self, addr, length, when="after", fix_endness=True):
		e = self.simmem_expression(self.memory, addr, length, when)
		if fix_endness:
			e = fix_endian(self.arch.endness, e)
		return e

	# Returns a concretized value of the content at a memory address
	def mem_concrete(self, *args, **kwargs):
		return symexec.utils.concretize_constant(self.mem_expr(*args, **kwargs))

	# Returns the SimValue representing the content of memory at an address
	def mem_value(self, addr, length, when="after", fix_endness=True):
		return self.expr_value(self.mem_expr(addr, length, when, fix_endness), when=when)

	# Stores a bitvector expression at an address in memory
	def store_mem(self, addr, content, when="after"):
		return self.store_simmem_expression(self.memory, addr, content, when)

	###############################
	### Stack operation helpers ###
	###############################

	# Push to the stack, writing the thing to memory and adjusting the stack pointer.
	@arch_overrideable
	def stack_push(self, thing):
		# increment sp
		sp = self.reg_expr(self.arch.sp_offset) + 4
		self.store_reg(self.arch.sp_offset, sp)

		return self.store_mem(sp, thing)

	# Pop from the stack, adjusting the stack pointer and returning the popped thing.
	@arch_overrideable
	def stack_pop(self):
		sp = self.reg_expr(self.arch.sp_offset)
		self.store_reg(self.arch.sp_offset, sp - 4)

		return self.mem_expr(sp, self.arch.bits / 8)

	# Returns a SimValue, popped from the stack
	@arch_overrideable
	def stack_pop_value(self):
		return SimValue(self.stack_pop(), self.constraints_after())

	# Read some number of bytes from the stack at the provided offset.
	@arch_overrideable
	def stack_read(self, offset, length, bp=False):
		if bp:
			sp = self.reg_expr(self.arch.bp_offset)
		else:
			sp = self.reg_expr(self.arch.sp_offset)

		return self.mem_expr(sp+offset, length)

	# Returns a SimVal, representing the bytes on the stack at the provided offset.
	@arch_overrideable
	def stack_read_value(self, offset, length, bp=False):
		return SimValue(self.stack_read(offset, length, bp), self.constraints_after())
