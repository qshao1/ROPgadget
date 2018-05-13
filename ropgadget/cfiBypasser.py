import re
import os
from os.path import dirname, abspath


class CFIBypasser(object):
    def __init__(self, filePath):
        self.__file_path = filePath
        self.__objFileExtension = "Dump.txt"
        self.__nmFileExtension = "Nm.txt"

    def test(self):
        self.getIndirectCalls()


    ## get function address and length pairs in a list
    def getFunctionAddressLengthPairs(self):

        # first load in the objdump file
        file_path = abspath(self.__file_path) + self.__objFileExtension
        with open(file_path) as f:
            objdump_txt = f.readlines()

        # load in the nm file
        file_path = abspath(self.__file_path) + self.__nmFileExtension
        with open(file_path) as f:
            nm_txt = f.readlines()

        # Use nm:
        # look for symbols in the form of "000003f0 T _start", only care about "T/t" (code) symbols
        # store all the symbol addresses
        searchString = " t "
        symbolAddresses = []
        for line in nm_txt:
            searchObj = re.search(searchString, line, re.IGNORECASE)
            if searchObj is not None:
                splitString = line.lower().split(searchString)
                symbolAddresses.append(int(splitString[0], 16))
        sortedSymbolAddresses = sorted(set(symbolAddresses))

        # Use objdump:
        # iterate through all the symbol addresses from nm
        # start from start of function, end at "ret"
        # count the function length by subtracting start address from ret address
        # store everything in pairs of [function address, function length]
        addressLengthPairs = {}
        for symbolAddress in sortedSymbolAddresses:
            symbolAddressString = hex(symbolAddress)[2::]  # filter out the initial 0x
            for idx, line in enumerate(objdump_txt):
                # search for a match of address followed by a colon "xxxx:"
                searchString = symbolAddressString + ":"
                if searchString in line:
                    # found the start of a symbol, look for the next ret
                    for lineIdx in range(idx, len(objdump_txt)):
                        searchString = "\tret"
                        if searchString in objdump_txt[lineIdx]:
                            retAddress = int(objdump_txt[lineIdx].split(":")[0], 16)
                            functionLength = retAddress - symbolAddress
                            if functionLength > 0:  # only care about non-zero length entries
                                addressLengthPairs[symbolAddress] = functionLength
                            break  # ret found; stop searching for ret
                    break  # symbol address found; stop searching
        return addressLengthPairs

    # get addresses and opcodes of lines that start with ff (indirect calls)
    def getIndirectCalls(self):

        file_path = abspath(self.__file_path) + self.__objFileExtension
        # print(file_path)
        with open(file_path) as f:
            objdump_txt = f.readlines()

        # declare result address and opcodes pair
        gadgetAddressOpcodesPairs = {}

        # Searching for indirect calls in each line
        for idx, line in enumerate(objdump_txt):
            # separate the address and the opcodes
            splitString = line.split(":")
            # only care about lines containing ':'
            if len(splitString) > 1:
                address = splitString[0]
                # parse the first part as hex address
                try:
                    addressInt = int(address, 16)
                except ValueError as ex:
                    continue

                opcodesAndDisass = splitString[1]
                splitOpcodesAndDisass = opcodesAndDisass.split()
                opcodes = ''
                if (len(splitOpcodesAndDisass) > 0) and (splitOpcodesAndDisass[0] == 'ff'):
                    for twoBytes in splitOpcodesAndDisass:
                        if len(twoBytes) == 2:  # opcode must be 2 bytes
                            try:
                                int(twoBytes, 16)  # opcode must be a hex number
                                opcodes += twoBytes
                            except ValueError as ex:
                                break
                    # add this series of opcodes to the corresponding gadget address
                    gadgetAddress = addressInt + len(opcodes)/2
                    gadgetAddressOpcodesPairs[gadgetAddress] = opcodes

        return gadgetAddressOpcodesPairs


