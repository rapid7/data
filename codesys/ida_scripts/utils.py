import ida_hexrays
import ida_struct
import ida_bytes
import ida_idp
import idc

from collections import namedtuple

from HRAST import traverse, Matcher, Patterns

def applyHRASTPatterns(ea, componentname, patterns, debug=True):
    pats = []
    for i in patterns:
        pats.append((eval(i[0], globals(), locals()), i[1], i[2]))

    fcn = ida_hexrays.decompile(ea)

    for i in pats:
        func_proc = traverse.FuncProcessor(fcn)
        matcher = Matcher.Matcher(func_proc.fcn, None, extra_ctx={"componentname": componentname})
        matcher.set_pattern(i[0])
        matcher.chain = i[2]
        matcher.replacer = i[1]
        func_proc.pattern = matcher
        func_proc.DEBUG = debug
        func_proc.traverse_function()

    ida_hexrays.mark_cfunc_dirty(ea)


def iterateStruct(ea, typename, cbStop):
    s = _get_struct_dict(typename)
    s_size = _get_struct_size(typename)
    pytype = namedtuple(typename, [x for x in s.keys()])

    start_addr = ea
    cur_addr = ea
    while True:
        sm = pytype(*[_get_struct_member(cur_addr, s, membername) for membername in s.keys()])
        
        if cbStop(cur_addr, sm):
            break

        yield sm
        cur_addr += s_size


def autocreateStructArray(ea, typename, cbStop, includeSentinel=True):
    s_size = _get_struct_size(typename)
    arrlen = len(list(iterateStruct(ea, typename, cbStop)))
    if includeSentinel: arrlen += 1
    ida_bytes.del_items(ea, 0, arrlen * s_size)
    ida_bytes.create_data(ea, ida_bytes.FF_STRUCT, arrlen * s_size, ida_struct.get_struc_id(typename))


def adjustFunctionPointer(ea):
    if ida_idp.get_idp_name() == "arm":
        if idc.get_sreg(ea, "T") == 1:
            return ea & 0xFFFFFFFE

    return ea


def _get_struct_dict(name):
    struct = {}

    s = ida_struct.get_struc(ida_struct.get_struc_id(name))
    m_id = 0
    while m_id != -1:
        m = s.get_member(m_id)
        struct[ida_struct.get_member_name(m.id)] = {"soff": m.soff, "eoff": m.eoff}
        m_id = ida_struct.get_next_member_idx(s, m.soff)

    return struct


def _get_struct_size(name):
    s = ida_struct.get_struc(ida_struct.get_struc_id(name))
    return ida_struct.get_max_offset(s)


def _get_struct_member(addr, s, member_name):
    member_addr = addr + s[member_name]["soff"]
    member_size = s[member_name]["eoff"] - s[member_name]["soff"]

    if member_size == 1:    return ida_bytes.get_byte(member_addr)
    if member_size == 2:    return ida_bytes.get_16bit(member_addr)
    if member_size == 4:    return ida_bytes.get_32bit(member_addr)
    if member_size == 8:    return ida_bytes.get_64bit(member_addr)

    assert(False), "Unhandled member size {}".format(member_size)
    return None
