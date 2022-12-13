#!/usr/bin/python3

from sys import byteorder

p10 = ( 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 )
p8 = ( 6, 3, 7, 4, 8, 5, 10, 9 )

p4 = ( 2, 4, 3, 1 )

ip = ( 2, 6, 3, 1, 4, 8, 5, 7 )
iip = ( 4, 1, 3, 5, 7, 2, 8, 6 )

ep = (4, 1, 2, 3, 2, 3, 4, 1)

sw = (5, 6, 7, 8, 1, 2, 3, 4)

s0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]

s1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]

k = 0b01101011

def leftShift(input):
    shiftList = [None] * 10
    shiftList[0:9] = input[1:10]
    shiftList[4] = input[0]
    shiftList[9] = input[5]
    return shiftList

def binList(binVal, len):
    resList = [None] * len
    resList = [int(i) for i in format(binVal, f"0{len}b")]
    return resList

# masterKey is an integer 0 - 1023 or 10 bits.
def keyGen(masterKey):
    # Create a list with the binary representation of the master key
    keyList = binList(masterKey, 10)
    
    # Permute the key using the p10 function
    p10KeyList = applyPTable(keyList, p10)
    
    shift1 = leftShift(p10KeyList)
    
    shift2 = leftShift(shift1)
    shift2 = leftShift(shift2)
    
    k1 = applyPTable(shift1, p8)
    k2 = applyPTable(shift2, p8)
    
    return (k1, k2)

def applyPTable(input, pTable):
    resList = [None] * len(pTable)
    for index, perm in enumerate(pTable):
        resList[index] = input[perm - 1]
    return resList

def fk(input, key):
    p1 = input[:4]
    p2 = input[4:]
    epList = applyPTable(p2, ep)
    # xor with key
    for (index, val) in enumerate(epList):
        epList[index] = val ^ key[index]
    e1 = epList[:4]
    e2 = epList[4:]

    # sbox
    e1 = applySBox(e1, s0)
    e2 = applySBox(e2, s1)
    #combine + p4
    resList = applyPTable(e1 + e2, p4)
    
    for (index, val) in enumerate(resList):
        resList[index] = val ^ p1[index]
    return resList + p2

def applySBox(input, sBox):
    row = (input[0] << 1) + input[3]
    col = (input[1] << 1) + input[2]
    res = sBox[row][col]
    return binList(res, 2)

def encrypt(input, key):
    (k1, k2) = keyGen(key)
    # convert text to list
    resList = binList(input, 8)
    # apply ip
    resList = applyPTable(resList, ip)
    # apply fk k1
    resList = fk(resList, k1)
    # sw
    resList = applyPTable(resList, sw)
    # apply fk k2
    resList = fk(resList, k2)
    # ip -1
    resList = applyPTable(resList, iip)
    
    res = ''.join(map(str, resList))
    
    return int(res, 2)

def decrypt(input, key):
    (k1, k2) = keyGen(key)
    # convert text to list
    resList = binList(input, 8)
    # apply ip
    resList = applyPTable(resList, ip)
    # apply fk k1
    resList = fk(resList, k2)
    # sw
    resList = applyPTable(resList, sw)
    # apply fk k2
    resList = fk(resList, k1)
    # ip -1
    resList = applyPTable(resList, iip)
    
    res = ''.join(map(str, resList))
    
    return int(res, 2)

if __name__ == "__main__":
    # test = binList(0b10101001, 8)
    # k1 = binList(0b10100100, 8)
    # print(fk(test, k1))
    usrin = input("Enter the password to save: ")
    key = input("Enter your secure key (0 - 1023): ")
    
    ct = []
    for char in usrin:
        ct.append(encrypt(ord(char), int(key)))
    
    with open("database.key", "wb") as f:
        for val in ct:
            print(f"val = {val}")
            print(format(val, '#010b'))
            f.write(val.to_bytes(1, byteorder='big'))
    
    pt = ''
    with open("database.key", "rb") as f:
        byte = f.read(1)
        while byte != b"":
            val = int.from_bytes(byte, byteorder='big')
            print(f"byte = {val}")
            pt += chr(decrypt(val, int(key)))
            byte = f.read(1)

    print(f"Plain text = {pt}")