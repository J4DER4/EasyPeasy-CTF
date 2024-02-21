#!/usr/bin/python3 -u

from pwn import *


#VAR

offset = 50000
maxchunk = 1000
host = 'mercury.picoctf.net'
port = 36981


#FUNC
    #Used for decoding key values
def find_key(original_char, result):
    return ord(original_char) ^ int("0x" + result, 16)

    #DECODER
def decoder(list, keychain):
    x=0
    output_list=[]
    print("-------------------")
    for i in list:
        #Start decrypt
        print("start value (hex): ", i)

        #digest hex to int unicode char
        i = (int(i,16))
        print("-> Digested to int: ",i)

        #digest int unicode char to char
        i = chr(i).replace("\n","")
        print("-> Digested to Unicode: ",i)

        # XOR with keypair to decrypted unicode value
        i = xor_func(i,keychain[x])
        print("-> XOR:ed with key(",keychain[x],"): ",i)
        #Encode to ASCII
        i = chr(i)
        print("=> Result : ",i)
        print("-------------------")
        output_list.append(i)
        flag = ''.join(output_list).rstrip()
        x+=1

        #STATS & RESULTS
    print("FOR ENCRYPTED FLAG: [",encrypted_flag,"]")
    print("... With offset of: ", offset, "\n")
    print( "DECODED STRING: ",flag,"  STRING LENGTH: ", output_list.__len__())
    print("KEYCHAIN: ", keychain )
    print(f"FLAG= picoCTF{{{flag}}}")


    #SWITCHER
def xor_func (normal_char, key_value):
    return ord(normal_char) ^ key_value

    #FLAG SPLITTER
def split_flag_to_list(encrypted_flag): 
    return [encrypted_flag[i:i+2] for i in range(0, len(encrypted_flag), 2)]




#START

original_char = b'1'  
keychain = []

print("Starting...\n")
r = remote(host, port)
    #GRAB ENCODED FLAG
r.recvuntil(b"flag!\n")
encrypted_flag = r.recvline().decode().replace("\n","")
print("Encrypted flag: ", encrypted_flag,"\n")

    #TRAVEL TO OFFSET (Wrap around the keys)
print("\nTRAVELING TO OFFSET: ",offset,"\n")
counter = offset - len(unhex(encrypted_flag))

while counter > 0:
    print("---Offset left until destination: ", counter)
    r.recvuntil(b"?")
    #copied code :/
    payload_size = min(maxchunk, counter)
    #send payload to traverse
    r.sendline(original_char*payload_size)

    counter-= payload_size
    

    #DUMP KEYCHAIN
print("\nSTARTING DUMP AT INDEX: ",50000-offset,"\n")
i = 0
while i < 32:
    r.recvuntil(b"?")
    r.sendline(original_char)
    r.recvline()
    result = r.recvline().decode().replace("\n","")
    print("Appending keychain with: ", find_key(original_char,result), " With value of: ",result)
    keychain.append(find_key(original_char,result))
    print("------------")
    i+=1
    
print("\nResulting keychain: ",keychain)

    #SPLIT FLAG
split_flag = split_flag_to_list(encrypted_flag)
print("\n Splitted Flag", split_flag)

    #DECODE WITH KEYCHAIN OBTAINED
print("\nStarting decoding with keychain")
    #rest is done in decoder()
decoder(split_flag,keychain)
print("\n")
r.close

