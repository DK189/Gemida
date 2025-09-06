import idaapi
import idc
import idautils
from . import ida_utils, llm

MAX_TOKENS = 200_000

def process_current_function():
    ea = idc.here()
    func = idaapi.get_func(ea)
    if not func:
        idaapi.msg("[Gemida] No function found at cursor.\n")
        return
    func_name = idc.get_func_name(func.start_ea)
    idaapi.msg(f"[Gemida] Analyzing current function: {func_name}\n")

    group = ida_utils.collect_function_group(func.start_ea, MAX_TOKENS)
    results = llm.analyze_functions(group)

    for old, info in results.items():
        ea = idc.get_name_ea_simple(old)
        if ea == idc.BADADDR:
            continue

        new_name = info.get("new_name", old)
        comment = info.get("comment")

        # Rename chỉ khi khác tên cũ
        if new_name and new_name != old:
            ida_utils.rename_function(old, new_name)

        # Set comment chỉ khi có comment hợp lệ
        if comment and comment.strip():
            ida_utils.set_function_comment(ea, comment)


def process_all_functions():
    idaapi.msg("[Gemida] Analyzing all functions in project...\n")

    all_funcs = list(idautils.Functions())
    groups = ida_utils.group_functions_by_tokens(all_funcs, MAX_TOKENS)

    for idx, group in enumerate(groups, 1):
        idaapi.msg(f"[Gemida] Analyzing group {idx}/{len(groups)} with {len(group)} functions\n")
        results = llm.analyze_functions(group)
        for old, info in results.items():
            ea = idc.get_name_ea_simple(old)
            if ea == idc.BADADDR:
                continue

            new_name = info.get("new_name", old)
            comment = info.get("comment")

            # Rename chỉ khi khác tên cũ
            if new_name and new_name != old:
                ida_utils.rename_function(old, new_name)

            # Set comment chỉ khi có comment hợp lệ
            if comment and comment.strip():
                ida_utils.set_function_comment(ea, comment)

