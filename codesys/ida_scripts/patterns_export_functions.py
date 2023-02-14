# Should match stuff like this
# v2 = CmpCAASegBufferMan_pfCMRegisterAPI((CMP_EXT_FUNCTION_REF *)&unk_8835A48, 0, 1, 16409);

import idaapi
import ida_name
import idc

idaapi.require("utils")


register_functions_call_without_cast = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.VarExpr(),
        Patterns.CallExprExactArgs(
            Patterns.ObjBind("fcn"),
            [
                Patterns.ObjBind("tbl"),
                Patterns.NumberExpr(Patterns.NumberConcrete(0)),
                Patterns.BindExpr('external', Patterns.NumberExpr()),
                Patterns.NumberExpr()
            ]
        )
    )
)
"""

register_functions_call_with_cast = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.VarExpr(),
        Patterns.CallExprExactArgs(
            Patterns.ObjBind("fcn"),
            [
                Patterns.CastExpr(
                    Patterns.RefExpr(
                        Patterns.ObjBind("tbl")
                    )
                ),
                Patterns.NumberExpr(Patterns.NumberConcrete(0)),
                Patterns.BindExpr('external', Patterns.NumberExpr()),
                Patterns.NumberExpr()
            ]
        )
    )
)
"""

register_functions_call_ref_without_cast = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.VarExpr(),
        Patterns.CallExprExactArgs(
            Patterns.ObjBind("fcn"),
            [
                Patterns.RefExpr(
                    Patterns.ObjBind("tbl")
                ),
                Patterns.NumberExpr(Patterns.NumberConcrete(0)),
                Patterns.BindExpr('external', Patterns.NumberExpr()),
                Patterns.NumberExpr()
            ]
        )
    )
)
"""


def xx(idx, ctx):
    external = ctx.get_expr('external')[0]
    fcn = ctx.get_obj('fcn')
    tbl = ctx.get_obj('tbl')

    function_addr = utils.adjustFunctionPointer(fcn.addr)
    function_name = ida_name.get_name(function_addr)
    table_addr = tbl.addr
    is_external = external.numval() == 1

    # rename the table
    if is_external:
        ida_name.set_name(table_addr, ctx.extra_ctx["componentname"] + "_ExternalsTable")
    else:
        ida_name.set_name(table_addr, ctx.extra_ctx["componentname"] + "_ItfTable")

    # create the struct
    utils.autocreateStructArray(table_addr, "CMP_EXT_FUNCTION_REF", lambda addr, sm: sm.pfExtCall == 0)

    # rename all functions in the struct
    for component in utils.iterateStruct(table_addr, "CMP_EXT_FUNCTION_REF", lambda addr, sm: sm.pfExtCall == 0):
        func_addr = utils.adjustFunctionPointer(component.pfExtCall)
        str_addr = component.pszExtCallName

        func_name = ctx.extra_ctx["componentname"] + "_" + idc.get_strlit_contents(str_addr).decode("ASCII")
        ida_name.set_name(func_addr, func_name)


PATTERNS = [
    (register_functions_call_with_cast, xx, False),
    (register_functions_call_without_cast, xx, False),
    (register_functions_call_ref_without_cast, xx, False),
]
