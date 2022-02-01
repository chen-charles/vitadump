#!/usr/bin/env python3

# IDAPython 7.4

import os.path
import struct

import ida_auto, ida_bytes, ida_kernwin, ida_nalt
from idautils import *
from idc import *

INFO_SIZE = 0x5c
NAME_OFF = 4
NAME_LEN = 27
ENT_TOP_OFF = 0x24
ENT_END_OFF = 0x28
STUB_TOP_OFF = 0x2c
STUB_END_OFF = 0x30

EXPORT_NUM_FUNCS_OFF = 0x6
EXPORT_NID_OFF = 0x10
EXPORT_LIBNAME_OFF = 0x14
EXPORT_NID_TABLE_OFF = 0x18
EXPORT_ENTRY_TABLE_OFF = 0x1c

IMPORT_NUM_FUNCS_OFF = 0x6
IMPORT_LIBNAME_OFF = 0x14
IMPORT_LIBNAME_OFF2 = 0x10
IMPORT_NID_TABLE_OFF = 0x1c
IMPORT_NID_TABLE_OFF2 = 0x14
IMPORT_ENTRY_TABLE_OFF = 0x20
IMPORT_ENTRY_TABLE_OFF2 = 0x18

NORETURN_FUNCS = [0xB997493D, 0x391B5B74, 0x00CCE39C, 0x37691BF8, 0x2f2c6046]


def u32(bytes, start=0):
    return struct.unpack("<I", bytes[start:start + 4])[0]


def u16(bytes, start=0):
    return struct.unpack("<H", bytes[start:start + 2])[0]


def u8(bytes, start=0):
    return struct.unpack("<B", bytes[start:start + 2])[0]


def read_cstring(addr, max_len=0):
    s = ""
    ea = addr
    while True:
        c = ida_bytes.get_byte(ea)
        if c == 0:
            break
        ea += 1
        s += chr(c)
        if max_len and len(s) > max_len:
            break
    return s


def chunk(s, l):
    """
        Chunks S into strings of length L, for example:
        >>> chunk("abcd", 2)
        ["ab", "cd"]
        >>> chunk("abcde", 2)
        ['ab', 'cd', 'e']
    """
    return [s[i:i + l] for i in range(0, len(s), l)]


nid_table = dict()

def load_nids(filename):
    if not os.path.exists(filename):
        print("cannot find nids.txt, NIDs won't be resolved")
        return
    fin = open(filename, "r")
    for line in fin.readlines():
        line = line.split()
        nid_table[int(line[0], 16)] = line[1]
    fin.close()
    print("Loaded {} NIDs".format(len(nid_table)))


def resolve_nid(nid):
    if nid in nid_table:
        return nid_table[nid]
    return ""

used_names = dict()

def rename_function(ea, name, suffix):
    """
        Renames a function, optionally adding a _XX suffix to make sure
        all names are unique.
    """
    name = name + suffix
    if name in used_names:
        used_names[name] += 1
        name += "_{}".format(used_names[name])
    else:
        used_names[name] = 0

    set_name(ea, name, SN_CHECK)

def process_nid_table(nid_table_addr, entry_table_addr, num_funcs, libname, name_suffix=""):
    if num_funcs == 0:
        return

    nids = get_bytes(nid_table_addr, 4 * num_funcs)
    funcs = get_bytes(entry_table_addr, 4 * num_funcs)

    if not nids or not funcs:
        print("NID table at 0x{0:x} is not supported, bailing out!".format(nid_table_addr))
        return

    for nid, func in zip(chunk(nids, 4), chunk(funcs, 4)):
        nid = u32(nid)
        func = u32(func)
        print("nid {} => func {}".format(hex(nid), hex(func)))
        t_reg = func & 1  # 0 = ARM, 1 = THUMB
        func -= t_reg
        for i in range(4):
            split_sreg_range(func + i, "T", t_reg, SR_user)
        add_func(func, BADADDR)

        actual_name = name = resolve_nid(nid)
        if not name:
            name = "{}_{:08X}".format(libname, nid)

        rename_function(func, name, name_suffix)

        if nid in NORETURN_FUNCS:
            set_func_attr(func, FUNCATTR_FLAGS, FUNC_NORET)

        # add a comment to mangled functions with demangled name, but only for imports
        # or otherwise when ida wouldn't do it itself because of non empty suffix
        if actual_name.startswith("_Z") and name_suffix:
            demangled = demangle_name(actual_name, get_inf_attr(INF_LONG_DN))
            if demangled != "":
                set_func_cmt(func, demangled, 1)


def process_export(exp, libname):
    num_funcs = u16(exp, EXPORT_NUM_FUNCS_OFF)
    nid_table = u32(exp, EXPORT_NID_TABLE_OFF)
    entry_table = u32(exp, EXPORT_ENTRY_TABLE_OFF)
    libname_addr = u32(exp, EXPORT_LIBNAME_OFF)
    nid = u32(exp, EXPORT_NID_OFF)
    libname = ""
    if libname_addr:
        libname = read_cstring(libname_addr, 255)

    print("{} with NID 0x{:x}".format(libname, nid))

    process_nid_table(nid_table, entry_table, num_funcs, libname)


def process_import(imp):
    num_funcs = u16(imp, IMPORT_NUM_FUNCS_OFF)
    nid_table = u32(imp, IMPORT_NID_TABLE_OFF if len(imp) == 0x34 else IMPORT_NID_TABLE_OFF2)
    entry_table = u32(imp, IMPORT_ENTRY_TABLE_OFF if len(imp) == 0x34 else IMPORT_ENTRY_TABLE_OFF2)
    libname_addr = u32(imp, IMPORT_LIBNAME_OFF if len(imp) == 0x34 else IMPORT_LIBNAME_OFF2)

    if not libname_addr:
        return

    libname = read_cstring(libname_addr, 255)
    process_nid_table(nid_table, entry_table, num_funcs, libname, "_imp")


def process_module(module_info_addr):
    module_info = get_bytes(module_info_addr, INFO_SIZE)
    name = module_info[NAME_OFF:NAME_OFF+NAME_LEN].strip(b"\x00")
    ent_top = u32(module_info, ENT_TOP_OFF)
    ent_end = u32(module_info, ENT_END_OFF)
    ent_len = ent_end - ent_top
    stub_top = u32(module_info, STUB_TOP_OFF)
    stub_end = u32(module_info, STUB_END_OFF)
    stub_len = stub_end - stub_top
    print("Library {} {}".format(name, hex(module_info_addr)))

    exports = []
    base_addr = addr = module_info_addr + INFO_SIZE
    while addr - base_addr < ent_end - ent_top:
        size = u8(get_bytes(addr, 1))
        exports.append((addr, size))
        addr += size

    imports = []
    base_addr = addr
    while addr - base_addr < stub_end - stub_top:
        size = u8(get_bytes(addr, 1))
        imports.append((addr, size))
        addr += size

    # We need to process imports first so that noreturn functions are found
    for addr, size in imports:
        process_import(get_bytes(addr, size))
    for addr, size in exports:
        process_export(get_bytes(addr, size), name)


def find_module_info(velf_name):
    with open(velf_name, "rb") as f:
        ehdr = f.read(52)  # 32-bit ELF ehdr size

    assert ehdr[:4] == b"\x7fELF", "not an ELF file"
    assert ehdr[4] == 1, "not a 32-bit ELF file"
    
    e_entry = ehdr[0x18:0x18+4]
    e_entry = struct.unpack('<L', e_entry)[0]
    
    print("e_entry=", hex(e_entry), sep="")

    seg_idx = e_entry >> 30
    seg_off = e_entry & 0x3fffffff
    
    process_module(ida_segment.getnseg(seg_idx).start_ea + seg_off)


def find_strings():
    seg_start = seg_end = 0

    while seg_start != BADADDR:
        seg_start = get_next_seg(seg_start)

        try:
            seg_end = get_segm_end(seg_start)
        except AssertionError:
            continue

        bytes = get_bytes(seg_start, seg_end - seg_start)

        if not bytes:
            continue

        start = 0
        while start < len(bytes):
            end = start
            while end < len(bytes) and bytes[end] >= 0x20 and bytes[end] <= 0x7e:
            #ord(bytes[end].decode("utf-8")) >= 0x20 and ord(bytes[end].decode("utf-8")) <= 0x7e:
                end += 1
            if end - start > 8 and not is_code(get_full_flags(seg_start + start)):
                ida_bytes.create_strlit(seg_start + start, 0, get_inf_attr(INF_STRTYPE))
            start = end + 1

def is_reg_call_safe(reg):
	if reg[0] == "R":
		return int(reg[1:]) > 3
	else:
		return reg in ["LR", "SP"]

def add_xrefs():
    """
        Searches for MOV / MOVT pair, probably separated by few instructions,
        and adds xrefs to things that look like addresses
    """
    addr = 0
    while addr != BADADDR:
        addr = next_head(addr)
        if print_insn_mnem(addr) == "MOV":
            reg = print_operand(addr, 0)
            if print_operand(addr, 1)[0] != "#":
                continue
            val = get_operand_value(addr, 1)
            found = False
            next_addr = addr
            for x in range(16): # next 16 instructions
                next_addr = next_head(next_addr)
                if print_insn_mnem(next_addr) in ["B", "BX", "BL", "BLX"] and not is_reg_call_safe(reg):
                    break
                if print_insn_mnem(next_addr) == "MOVT" and print_operand(next_addr, 0) == reg:
                    if print_operand(next_addr, 1)[0] == "#":
                        found = True
                        val += get_operand_value(next_addr, 1) * (2 ** 16)
                    break
                if print_operand(next_addr, 0) == reg or print_operand(next_addr, 1) == reg:
                    break
            if val & 0xFFFF0000 == 0:
                continue
            if found:
                # pair of MOV/MOVT
                op_offset(addr, 1, REF_LOW16, val, 0, 0)
                op_offset(next_addr, 1, REF_HIGH16, val, 0, 0)
            else:
                # a single MOV instruction
                op_plain_offset(addr, 1, 0)


def remove_chunks(ea):
    """
        Remove chunks from imported functions because they make no sense.
    """
    chunks = list(Chunks(ea))
    if len(chunks) > 1:
        for chunk in chunks:
            if chunk[0] != ea:
                remove_fchunk(ea, chunk[0])
                add_func(chunk[0], BADADDR)
        ida_auto.auto_wait()


def resolve_local_nids():
    """
        Finds resolved imported functions and renames them to actual names,
        if the module that provides that function is available and loaded.
        Only works for user-level imports.
    """
    ea = get_next_func(next_addr(0))
    while ea != BADADDR:
        next = next_head(ea)
        # print(print_insn_mnem(ea), print_insn_mnem(next), print_operand(next, 0))
        if print_insn_mnem(ea) == "MOV" and print_insn_mnem(next) == "BX" and print_operand(next, 0) in ["R12", "LR"]:
            remove_chunks(ea)
            actual_name = get_func_name(ea)
            if actual_name and not actual_name.startswith("sub_") and actual_name.endswith("_imp"):
                rename_function(ea, actual_name[:- len("_imp")], "")
        ea = get_next_func(ea)


def main():
    velf_name = ida_nalt.get_input_file_path()
    if not os.path.isfile(velf_name):
        velf_name = ida_kernwin.ask_file(0, velf_name, "Open Source Vita ELF File")

    path = os.path.dirname(os.path.realpath(__file__))
    # load_nids(os.path.join(path, "nids.txt"))

    nids_path = os.path.join(path, "nids.txt")
    if not os.path.isfile(nids_path):
        nids_path = load_nids(ida_kernwin.ask_file(0, nids_path, "Open nids.txt"))
    load_nids(nids_path)

    print("Finding module_info")
    find_module_info(velf_name)
    print("Waiting")
    ida_auto.auto_wait()
    print("Finding strings")
    find_strings()
    print("Adding xrefs")
    add_xrefs()
    resolve_local_nids()

if __name__ == "__main__":
    main()
