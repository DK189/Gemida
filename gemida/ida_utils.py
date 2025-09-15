import idaapi
import idc
import ida_hexrays

# -----------------------------------------------------------------------------
# Helper: safe decompile
# -----------------------------------------------------------------------------
def _safe_decompile(ea):
    try:
        name = idc.get_func_name(ea)
        # Bỏ qua hàm chưa rename (sub_XXXX, nullsub_XX)
        if not (name.startswith("sub_") or name.startswith("nullsub_")):
            return None
        return ida_hexrays.decompile(ea)
    except Exception:
        return None

# -----------------------------------------------------------------------------
# Visitor to collect callees from pseudocode
# -----------------------------------------------------------------------------
class CallCollector(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.calls = []

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            # direct call to function
            if e.x.op == ida_hexrays.cot_obj:
                self.calls.append(e.x.obj_ea)
        return 0

def _collect_callees(cfunc):
    cc = CallCollector()
    cc.apply_to(cfunc.body, None)  # traverse the C-tree
    return cc.calls

# -----------------------------------------------------------------------------
# Collect function + callees (bounded by token limit)
# -----------------------------------------------------------------------------
def collect_function_group(start_ea, max_tokens=200_000):
    visited, queue, group, total_size = set(), [start_ea], {}, 0
    while queue:
        ea = queue.pop()
        if ea in visited:
            continue
        visited.add(ea)

        cfunc = _safe_decompile(ea)
        if not cfunc:
            continue
        pseudocode = str(cfunc)
        size = len(pseudocode.split())
        if total_size + size > max_tokens:
            break

        func_name = idc.get_func_name(ea)
        group[func_name] = pseudocode
        total_size += size

        # collect callees via ctree visitor
        for callea in _collect_callees(cfunc):
            callee_func = idaapi.get_func(callea)
            if callee_func:
                queue.append(callee_func.start_ea)
    return group

# -----------------------------------------------------------------------------
# Group functions in token-limited batches
# -----------------------------------------------------------------------------
def group_functions_by_tokens(funcs, max_tokens=200_000):
    groups, group, total = [], {}, 0
    for ea in funcs:
        cfunc = _safe_decompile(ea)
        if not cfunc:
            continue
        pseudocode = str(cfunc)
        size = len(pseudocode.split())
        if total + size > max_tokens and group:
            groups.append(group)
            group, total = {}, 0
        group[idc.get_func_name(ea)] = pseudocode
        total += size
    if group:
        groups.append(group)
    return groups

# -----------------------------------------------------------------------------
# Rename function safely
# -----------------------------------------------------------------------------
def rename_function(old_name, new_name):
    if old_name.startswith("sub_") or old_name.startswith("nullsub_"):
        ea = idc.get_name_ea_simple(old_name)
        if ea != idc.BADADDR:
            idaapi.msg(f"[Gemida] Renaming {old_name} -> {new_name}\n")
            idc.set_name(ea, new_name, idc.SN_AUTO)

# -----------------------------------------------------------------------------
# Add comment to function
# -----------------------------------------------------------------------------
def set_function_comment(ea, comment):
    if ea != idc.BADADDR and comment:
        idaapi.msg(f"[Gemida] Adding comment to {idc.get_func_name(ea)}\n")
        idc.set_func_cmt(ea, comment, 0)
