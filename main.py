#!/usr/bin/python3

p10 = ( 3, 5, 2, 7, 4, 10, 1, 9, 8, 6 )
p8 = ( 6, 3, 7, 4, 8, 5, 10, 9 )

p4 = ( 2, 4, 3, 1 )

ip = ( 2, 6, 3, 1, 4, 8, 5, 7 )
iip = ( 4, 1, 3, 5, 7, 2, 8, 6 )

ep = (4, 1, 2, 3, 2, 3, 4, 1)

sw = (5, 6, 7, 8, 1, 2, 3, 4)

s0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
s1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

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
    print(f"keyList = {keyList}")
    
    # Permute the key using the p10 function
    p10KeyList = applyPTable(keyList, p10)
    
    print(f"p10KeyList = {p10KeyList}")
    
    shift1 = leftShift(p10KeyList)
    print(f"shift1 = {shift1}")
    
    shift2 = leftShift(shift1)
    shift2 = leftShift(shift2)
    print(f"shift2 = {shift2}")
    
    k1 = applyPTable(shift1, p8)
    k2 = applyPTable(shift2, p8)
    
    print(f"{k1} + {k2}")
    
    return (k1, k2)

def applyPTable(input, pTable):
    resList = [None] * len(pTable)
    for index, perm in enumerate(pTable):
        resList[index] = input[perm - 1]
    return resList

def fk(input, key):
    p1 = input[:4]
    p2 = input[4:]
    epTable = applyPTable(p2, ep)
    # xor with key
    
    # split 4 4
    
    # sbox
    
    #combine + p4
    
    return

def applySBox(input, sBox):

    return

def encrypt():
    # convert text to list
    binList
    # apply ip
    ipList = applyPTable(binList, ip)
    # apply fk k1
    fk()
    # sw
    
    # apply fk k2
    
    # ip -1
    return

if __name__ == "__main__":
    print(1^1)
    (k1, k2) = keyGen(int("1010000010", 2))
