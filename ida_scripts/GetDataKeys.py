from idaapi import *
from idautils import *


def get_string(addr):
    out = ""
    while True:
        if get_wide_byte(addr) != 0:
            out += chr(get_wide_byte(addr))
        else:
            break
        addr += 1
    return out


def get_string_from_head(head):
    refs = DataRefsFrom(head)
    for ref in refs:
        refs2 = DataRefsFrom(ref)
        for ref2 in refs2:
            stringval = get_string(ref2)
            return stringval


def get_string_from_babyhead(head):
    refs = DataRefsFrom(head)
    for ref in refs:
        stringval = get_string(ref)
        return stringval


map = {}


def dumpkvp(functionName, addr, key):
    if 'getMissionPlateFileName' in functionName:
        return
    if functionName.count('_') == 1 and key in functionName:
        for (startea, endea) in Chunks(addr):
            for head in Heads(startea, endea):
                if 'MOV' in generate_disasm_line(head):
                    operand = generate_disasm_line(head)
                    if operand.count(':') == 0:
                        continue
                    functionName = functionName[3:]
                    if functionName.count('Mst') == 0:
                        continue
                    functionName = functionName[:functionName.index('Mst') + 3]
                    functionName = ''.join([i for i in functionName if not i.isdigit()])
                    stringval = get_string_from_head(head)
                    if not (functionName in map):
                        if not stringval:
                            stringval = 'F_BATTLE_SCRIPT_MST'
                        map[functionName] = stringval
                        files[map[functionName]] = {}
                    else:
                        files[map[functionName]][key[4:]] = stringval

files = {}
# for funcea in Functions(0xb00000, 0x13ea010):
#     functionName = get_func_name(funcea)
#     dumpkvp(functionName, funcea, 'MstName')
for funcea in Functions(0xb00000, 0x13ea010):
    functionName = get_func_name(funcea)
    dumpkvp(functionName, funcea, 'MstName')
    dumpkvp(functionName, funcea, 'FileName')
    dumpkvp(functionName, funcea, 'FileKey')

for addr in Functions(0xb00000, 0x13ea010):
    functionName = get_func_name(addr)
    if 'sub_FE51E0' in functionName:
        stringval = ""
        name = ""
        key = ""
        for (startea, endea) in Chunks(addr):
            for head in Heads(startea, endea):
                operand = generate_disasm_line(head)
                if 'MOV' in operand and 'ds:(off' in operand:
                    stringval = get_string_from_head(head)
                if 'LEA' in operand and not (stringval == ''):
                    if key == '':
                        key = get_string_from_babyhead(head)
                    else:
                        name = get_string_from_babyhead(head)
                        files[stringval] = {}
                        files[stringval]['Name'] = name
                        files[stringval]['Key'] = key
                        key = ''
                        stringval = ''

sc = string_info_t()
for addr in Functions(0xb00000, 0x2000000):
    functionName = get_func_name(addr)
    if '_ZN15VersionInfoListC2Ev' in functionName:
        stringval = ""
        name = ""
        key = ""
        for (startea, endea) in Chunks(addr):
            for head in Heads(startea, endea):
                operand = generate_disasm_line(head)
                if 'MOV' in operand and 'ds:(off' in operand:
                    if 'EAX' in operand:
                        stringval = get_string_from_head(head)
                    if 'ECX' in operand:
                        name = get_string_from_head(head)
                        if stringval in files:
                            continue
                        files[stringval] = {}
                        files[stringval]['Name'] = name


def dumpkey(addr):
    for (startea, endea) in Chunks(addr):
        i = 0
        for head in Heads(startea, endea):
            i = i + 1
            if i > 0x10:
                continue
            operand = generate_disasm_line(head)
            if 'MOV' in operand and 'ds:(off' in operand:
                return get_string_from_head(head)
    return ''


start = get_segm_by_name(".data.rel.ro.local").start_ea
end = get_segm_by_name(".data.rel.ro").end_ea
print(hex(start))
print(hex(end))
a = 0x024548B4
print(hex(a), ' ', hex(idc.get_wide_dword(a)), ' ', idc.get_name(idc.get_wide_dword(a)), ' : ', dumpkey(idc.get_wide_dword(a)))
for addr in range(start, end):
    pointeraddr = idc.get_wide_dword(addr)
    pointername = idc.get_name(pointeraddr)
    if not ('sub_' in pointername or 'loc_' in pointername):
        continue
    stringval = dumpkey(pointeraddr)
    if '_MST' in stringval or 'F_TEXT' in stringval:
        if stringval in files:
            if 'Key' in files[stringval]:
                continue
        # name = files[stringval]['Name']
        name = dumpkey(idc.get_wide_dword(addr + 4))
        key = dumpkey(idc.get_wide_dword(addr + 8))
        # if name == nextstringval:
        files[stringval] = {}
        if not ('Name' in files[stringval]):
            files[stringval]['Name'] = name
        files[stringval]['Key'] = key

# print files
import json

filename = os.path.expanduser("~/files2.json")
with open(filename, 'w') as fp:
    json.dump(files, fp)
