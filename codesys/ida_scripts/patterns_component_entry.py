import idaapi
import ida_name
import ida_typeinf

idaapi.require("utils")

# Should match stuff like this
#  pInitStruct->pfExportFunctions = sub_8089550;
#  pInitStruct->pfImportFunctions = sub_8089600;
#  pInitStruct->pfGetVersion = sub_8089F78;
#  pInitStruct->pfHookFunction = (int (__cdecl *)(_DWORD, _DWORD *, _DWORD *))sub_8089F98;
#  pInitStruct->pfCreateInstance = (void *(__cdecl *)(_DWORD, _DWORD *))sub_8089500;
#  pInitStruct->pfDeleteInstance = (_DWORD (__cdecl *)(void *))sub_8089528;

init_struct_component_fill_with_cast = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.BindExpr('struct_access',
            Patterns.MemptrExpr(
                Patterns.VarExpr()
            )
        ),
        Patterns.CastExpr(
            Patterns.ObjBind("fcnPtr")
        )
    )
)
"""

init_struct_component_fill_without_cast = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.BindExpr('struct_access',
            Patterns.MemptrExpr(
                Patterns.VarExpr()
            )
        ),
        Patterns.ObjBind("fcnPtr")
    )
)
"""

init_struct_component_fill_with_cast_for_thumb = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.BindExpr('struct_access',
            Patterns.MemptrExpr(
                Patterns.VarExpr()
            )
        ),
        Patterns.CastExpr(
            Patterns.AddExpr(
                Patterns.RefExpr(
                    Patterns.ObjBind("fcnPtr")
                ),
                Patterns.NumberExpr(Patterns.NumberConcrete(1))
            )
        )
    )
)
"""

init_struct_component_fill_without_cast_for_thumb = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.BindExpr('struct_access',
            Patterns.MemptrExpr(
                Patterns.VarExpr()
            )
        ),
        Patterns.AddExpr(
            Patterns.RefExpr(
                Patterns.ObjBind("fcnPtr")
            ),
            Patterns.NumberExpr(Patterns.NumberConcrete(1))
        )
    )
)
"""

def init_struct_component_fill(idx, ctx):
    func_ptr_addr = utils.adjustFunctionPointer(ctx.get_obj('fcnPtr').addr)

    struct_access = ctx.get_expr('struct_access')[0]
    struct_member_offset = struct_access.m
    
    # get struct type by dereferencing pointer
    t = struct_access.get_ptr_or_array().type.get_pointed_object()

    # get struct member variable type info
    udt_member = idaapi.udt_member_t()
    udt_member.offset = struct_member_offset * 8
    t.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)

    struct_fptr_name = udt_member.name
    struct_fptr_type = udt_member.type.get_pointed_object()

    # rename the function pointer
    ida_name.set_name(func_ptr_addr, ctx.extra_ctx["componentname"] + "_" + struct_fptr_name)

    # set the type of the function pointer
    ida_typeinf.apply_tinfo(func_ptr_addr, struct_fptr_type, ida_typeinf.TINFO_DEFINITE)

PATTERNS = [
    (init_struct_component_fill_with_cast, init_struct_component_fill, False),
    (init_struct_component_fill_without_cast, init_struct_component_fill, False),
    (init_struct_component_fill_with_cast_for_thumb, init_struct_component_fill, False),
    (init_struct_component_fill_without_cast_for_thumb, init_struct_component_fill, False),
]




# Should match something like this
#  dword_891F074 = (int)pInitStruct->pfCMRegisterAPI;
#  dword_891F078 = (int)pInitStruct->pfCMRegisterAPI2;
#  dword_891F07C = (int)pInitStruct->pfCMGetAPI;
#  dword_891F080 = (int)pInitStruct->pfCMGetAPI2;
#  dword_891F08C = (int)pInitStruct->pfCMCallHook;
#  dword_891F084 = (int)pInitStruct->pfCMRegisterClass;
#  dword_891F088 = (int)pInitStruct->pfCMCreateInstance;

init_struct_component_private_cm_function_pointers_with_cast = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.ObjBind("fcnPtr"),
        Patterns.CastExpr(
            Patterns.BindExpr('struct_access',
                Patterns.MemptrExpr(
                    Patterns.VarExpr()
                )
            )
        )
    )
)
"""

init_struct_component_private_cm_function_pointers_without_cast = """Patterns.ExprInst(
    Patterns.AsgnExpr(
        Patterns.ObjBind("fcnPtr"),
        Patterns.BindExpr('struct_access',
            Patterns.MemptrExpr(
                Patterns.VarExpr()
            )
        )
    )
)
"""

def init_struct_component_private_cm_function_pointers(idx, ctx):
    func_ptr_addr = utils.adjustFunctionPointer(ctx.get_obj('fcnPtr').addr)

    struct_access = ctx.get_expr('struct_access')[0]
    struct_member_offset = struct_access.m
    
    # get struct type by dereferencing pointer
    t = struct_access.get_ptr_or_array().type.get_pointed_object()

    # get struct member variable type info
    udt_member = idaapi.udt_member_t()
    udt_member.offset = struct_member_offset * 8
    t.find_udt_member(udt_member, idaapi.STRMEM_OFFSET)

    struct_fptr_name = udt_member.name
    struct_fptr_type = udt_member.type

    # rename the function pointer
    ida_name.set_name(func_ptr_addr, ctx.extra_ctx["componentname"] + "_" + struct_fptr_name)

    # set the type of the function pointer
    ida_typeinf.apply_tinfo(func_ptr_addr, struct_fptr_type, ida_typeinf.TINFO_DEFINITE)

PATTERNS += [
    (init_struct_component_private_cm_function_pointers_with_cast, init_struct_component_private_cm_function_pointers, False),
    (init_struct_component_private_cm_function_pointers_without_cast, init_struct_component_private_cm_function_pointers, False)
]
