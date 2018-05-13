## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-17 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##

import re
import codecs
import cfiBypasser
import binascii
from capstone   import *
from struct     import pack

class Options(object):
    def __init__(self, options, binary, gadgets):
        self.__options = options
        self.__gadgets = gadgets
        self.__binary  = binary

        if options.filter:   self.__filterOption()
        if options.only:     self.__onlyOption()
        if options.range:    self.__rangeOption()
        if options.re:       self.__reOption()
        if options.badbytes: self.__deleteBadBytes()
        if options.callPreceded:
            cfiBypasserObj = cfiBypasser.CFIBypasser(self.__binary.getFileName())
            self.__functionAddressLengthPairs = cfiBypasserObj.getFunctionAddressLengthPairs()
            self.__gadgetAddressCallOpcodesPairs = cfiBypasserObj.getIndirectCalls()
            self.__callPrecededGadgets()
        if options.fullFunctionReuse:
            cfiBypasserObj = cfiBypasser.CFIBypasser(self.__binary.getFileName())
            self.__functionAddressLengthPairs = cfiBypasserObj.getFunctionAddressLengthPairs()
            self.__fullFunctionReuseGadgets()

    def __filterOption(self):
        new = []
        if not self.__options.filter:
            return
        filt = self.__options.filter.split("|")
        if not len(filt):
            return
        for gadget in self.__gadgets:
            flag = 0
            insts = gadget["gadget"].split(" ; ")
            for ins in insts:
                if ins.split(" ")[0] in filt:
                    flag = 1
                    break
            if not flag:
                new += [gadget]
        self.__gadgets = new

    def __onlyOption(self):
        new = []
        if not self.__options.only:
            return
        only = self.__options.only.split("|")
        if not len(only):
            return
        for gadget in self.__gadgets:
            flag = 0
            insts = gadget["gadget"].split(" ; ")
            for ins in insts:
                if ins.split(" ")[0] not in only:
                    flag = 1
                    break
            if not flag:
                new += [gadget]
        self.__gadgets = new

    def __rangeOption(self):
        new = []
        rangeS = int(self.__options.range.split('-')[0], 16)
        rangeE = int(self.__options.range.split('-')[1], 16)
        if rangeS == 0 and rangeE == 0:
            return
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            if vaddr >= rangeS and vaddr <= rangeE:
                new += [gadget]
        self.__gadgets = new

    def __reOption(self):
        new = []
        re_strs = []

        if not self.__options.re:
            return

        if '|' in self.__options.re:
            re_strs = self.__options.re.split(' | ')
            if 1 == len(re_strs):
                re_strs = self.__options.re.split('|')
        else:
            re_strs.append(self.__options.re)

        patterns = []
        for __re_str in re_strs:
            pattern = re.compile(__re_str)
            patterns.append(pattern)

        for gadget in self.__gadgets:
            flag = 1
            insts = gadget["gadget"].split(" ; ")
            for pattern in patterns:
                for ins in insts:
                    res = pattern.search(ins)
                    if res:
                        flag = 1
                        break
                    else:
                        flag = 0
                if not flag:
                    break
            if flag:
                new += [gadget]
        self.__gadgets = new

    def __fullFunctionReuseGadgets(self):
        def __isGadgetFullFunction(gadget):
            # Given a gadget, determine if it spans a full function
            result = False

            if arch & CS_MODE_64:
                formatting = "0x%016x"
            else:
                formatting = "0x%08x"
            gadget_addr = int(formatting % (gadget["vaddr"]), 16)

            # see if gadget address is in the function list
            if gadget_addr in list(self.__functionAddressLengthPairs.keys()):
                # compare gadget length with function length
                if self.__functionAddressLengthPairs[gadget_addr] == len(gadget["bytes"])-1:  # -1 for ret instruction
                    result = True
            return result

        arch = self.__binary.getArch()
        if arch == CS_ARCH_X86:
            initial_length = len(self.__gadgets)
            self.__gadgets = filter(__isGadgetFullFunction, self.__gadgets)
            print(
            "Options().fullFunctionReuse(): Filtered out {} gadgets.".format(initial_length - len(self.__gadgets)))
        else:
            print("Options().fullFunctionReuse(): Unsupported architecture.")



    def __callPrecededGadgets(self):

        def __isGadgetRelNearCallPreceded(gadget):
            # Given a gadget, determine if the bytes immediately preceding are a call instruction
            result = False
            prevBytes = gadget["prev"]
            if arch & CS_MODE_64:
                callPrecededExpressions = [
                    "\xe8[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",  # 64-bit near call
                ]
                formatting = "0x%016x"
            else:
                callPrecededExpressions = [
                    "\xe8[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",  # 32-bit near call
                ]
                formatting = "0x%08x"

            # find the call instruction and remember the target address
            map_result = map(lambda x: re.search(x, prevBytes), callPrecededExpressions)
            call_bytes_obj = next((matchBytes for matchBytes in map_result if matchBytes is not None), None)
            if call_bytes_obj is not None:
                call_bytes_idx = call_bytes_obj.start(0) + 1
                call_target = prevBytes[call_bytes_idx:]
                # target bytes need to be reversed to adjust for little endian-ness
                if self.__binary.getArchMode() & CS_MODE_BIG_ENDIAN:
                    call_target_addr = call_target
                else:
                    call_target_addr = call_target[::-1]

                call_target_addr_int = int(call_target_addr.encode('hex'), 16)
                if call_target_addr_int > 0x7FFFFFFF:
                    call_target_addr_int -= 0x100000000

                gadget_addr = int(formatting % (gadget["vaddr"]), 16)

                # calculate near call target address
                call_target_addr_int += gadget_addr
                if call_target_addr_int in list(self.__functionAddressLengthPairs.keys()):
                    result = True
            return result

        def __isGadgetIndirCallPreceded(gadget):
            # Given a gadget, determine if the bytes immediately preceding are a call instruction
            result = False
            prevBytes = gadget["prev"]
            callPrecededExpressions = [
                "\xff[\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$",
                "\xff[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]$"
            ]
            if arch & CS_MODE_64:
                formatting = "0x%016x"
            else:
                formatting = "0x%08x"

            # find the call instruction and remember the target address
            map_result = map(lambda x: re.search(x, prevBytes), callPrecededExpressions)
            call_bytes_obj = next((matchBytes for matchBytes in map_result if matchBytes is not None), None)
            if call_bytes_obj is not None:
                call_bytes_idx = call_bytes_obj.start(0)
                call_target = prevBytes[call_bytes_idx:]
                gadget_addr = int(formatting % (gadget["vaddr"]), 16)
                # check if this gadget is an indirect call preceded
                if gadget_addr in self.__gadgetAddressCallOpcodesPairs.keys():
                    # check the call opcodes match previous bytes
                    if binascii.hexlify(call_target) == self.__gadgetAddressCallOpcodesPairs[gadget_addr]:
                        result = True
            return result

        arch = self.__binary.getArch()
        if arch == CS_ARCH_X86:
            initial_length = len(self.__gadgets)
            self.__gadgets = filter(__isGadgetRelNearCallPreceded, self.__gadgets) + \
                                filter(__isGadgetIndirCallPreceded, self.__gadgets)
            print("Options().callPrecededGadgets(): Filtered out {} gadgets.".format(initial_length - len(self.__gadgets)))
        else:
            print("Options().callPrecededGadgets(): Unsupported architecture.")

    def __deleteBadBytes(self):
        archMode = self.__binary.getArchMode()
        if not self.__options.badbytes:
            return
        new = []
        #Filter out empty badbytes (i.e if badbytes was set to 00|ff| there's an empty badbyte after the last '|')
        #and convert each one to the corresponding byte
        bbytes = []
        for bb in self.__options.badbytes.split("|"):
            if '-' in bb:
                rng = bb.split('-')
                low = ord(codecs.decode(rng[0], "hex"))
                high = ord(codecs.decode(rng[1], "hex"))
                for i in range(low, high):
                    bbytes.append(chr(i))
            else:
                bbytes.append(codecs.decode(bb.encode("ascii"), "hex"))

        archMode = self.__binary.getArchMode()
        for gadget in self.__gadgets:
            gadAddr = pack("<L", gadget["vaddr"]) if archMode == CS_MODE_32 else pack("<Q", gadget["vaddr"])
            try:
                for x in bbytes:
                    if x in gadAddr: raise
                new += [gadget]
            except:
                pass
        self.__gadgets = new

    def getGadgets(self):
        return self.__gadgets

