import idaapi
import ida_name
import ida_idaapi
import idc

idaapi.require("patterns_component_entry")
idaapi.require("patterns_export_functions")
idaapi.require("utils")


ENTRY_FUNCTION_TYPE_STR = "int Entry(INIT_STRUCT *pInitStruct)"

def renameComponentListEntries(ea):
    utils.autocreateStructArray(ea, "StaticComponent", lambda addr, sm: sm.function == 0)

    for component in utils.iterateStruct(ea, "StaticComponent", lambda addr, sm: sm.function == 0):
        component_name = idc.get_strlit_contents(component.name).decode("ASCII")
        func_name = component_name + "__Entry"
        func_addr = utils.adjustFunctionPointer(component.function)

        ida_name.set_name(func_addr, func_name)
        idc.SetType(func_addr, ENTRY_FUNCTION_TYPE_STR)

        # clean up component entry functions
        tidyComponentEntryFunction(func_addr, component_name)

        # traverse exportFunctions function for component to find function tables
        tidyExportFunctionsFunction(component_name)


def tidyComponentEntryFunction(ea, componentname):
    utils.applyHRASTPatterns(ea, componentname, patterns_component_entry.PATTERNS)


def tidyExportFunctionsFunction(componentname):
    exportFunctions_ea = utils.adjustFunctionPointer(ida_name.get_name_ea(-1, componentname + "_pfExportFunctions"))

    if exportFunctions_ea == ida_idaapi.BADADDR:
        print(f"WARNING: Can't find function {componentname + '_pfExportFunctions'}. Not going to rename exported functions for this module.")
        return

    utils.applyHRASTPatterns(exportFunctions_ea, componentname, patterns_export_functions.PATTERNS)


def do_work(ea):
    renameComponentListEntries(ea)
