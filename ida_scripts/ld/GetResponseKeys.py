from idautils import *
from idaapi import *
from idc import GetDisasm
from idc_bc695 import Byte, GetFunctionName


def get_string(addr):
    out = ""
    while True:
        if Byte(addr) != 0:
            out += chr(Byte(addr))
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


requests = {}
keys = []
names = []

for addr in Functions(0x100000, 0x13ea010):
    functionName = GetFunctionName(addr)
    if 'GameResponseFactory18createResponseDataEPKc' in functionName:
        # if 'getResponseObject' in functionName:
        stringval = ""
        for (startea, endea) in Chunks(addr):
            for head in Heads(startea, endea):
                operand = GetDisasm(head)
                print '---------------------------------------------'
                print operand
                # if 'mov' in operand and 'ds:(off' in operand:
                if 'LDR' in operand and 'R1, =(' in operand:
                    stringval = get_string_from_head(head)
                    print stringval
                    keys.append(stringval)
                if 'Resp' in operand and 'se' in operand and 'C2' in operand:
                    reqname = operand[11:]
                    reqname = reqname[:reqname.index('Resp')]
                    reqname = ''.join([i for i in reqname if not i.isdigit()])
                    reqname = reqname[8:]
                    print reqname
                    # reqnamealt = 1
                    # origreqname = reqname
                    # while reqname in requests:
                    #	reqname = origreqname + str(reqnamealt)
                    #	reqnamealt = reqnamealt + 1
                    requests[stringval] = reqname
                    names.append(reqname)
                if 'MOV' in operand and 'R4, R0' in operand:
                    print get_string_from_head(head)
# print requests
import json

print len(keys)
print len(names)

filename = os.path.expanduser("~/keys.txt")
with open(filename, 'w') as fp:
    for line in keys:
        fp.write(line + '\n')

filename = os.path.expanduser("~/names.txt")
with open(filename, 'w') as fp:
    for line in names:
        fp.write(line + '\n')


filename = os.path.expanduser("~/response2.json")
with open(filename, 'w') as fp:
    json.dump(requests, fp)
