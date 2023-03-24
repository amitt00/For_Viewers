##AES GCM for aL En te Meter
#Amit Tiwari

import os
from Crypto.Cipher import AES
#INFORMATION
##################################
####Iterations to try

print("Enter text")
message=input()
message=message.replace(" ","")
tag123=message[-24:]
print("tag:",tag123)
counter123=message[:8]
print("counter:",counter123)
cipher_text123=message[8:-24]
print("ciphertext:",cipher_text123)



#value: Current : 2.15  #sent by server: server system title
counter00="0000024A"
cipher_text00="D954CE0E05C350"
tag00="0460F53018B3FB79AB1BADD5"

#value:: Frequency: 49.8 #sent by server: server system title
counter0="00000228"
cipher_text0="4EC6DEE4D211CB"
tag0= "7D2221887A1215EF3909A52E"

#Value:: Voltage: 229.50 #sent by server: server system title
counter3="000001FA"
cipher_text3="C202B50E47DDB3" 
tag3= "A4BD99131C7A9AA4087C653C"


#RegisterVoltage    #sent by client use client system title
counter4="01234705" 
cipher_text4="729269642DCF1DAB6C0680F037" 
tag4= "3E4C73325B1F2C4F38492B02"

#test
cipher_text1      = "C118B34831022FFA74F70BDF3395"
tag1              = "F85AE45DB51EBB6E30124EB1"
counter1="012346D2"

##Try 1
from Crypto.Cipher import AES

def encrypt_it(counter,plain_text):
    system_title ="4C4E434C49454E54"
    iv           =bytes.fromhex(system_title + str(counter))
    Ciphering_key=bytes.fromhex("31323334353637383930313233343536")
    aad          =bytes.fromhex("3031323334353637383930313233343536")
    cipher = AES.new(Ciphering_key, AES.MODE_GCM, iv,mac_len=12,) # nonce
    cipher.update(aad)
    try:
        text,tag = cipher.encrypt_and_digest(bytes.fromhex(plain_text))
        print("Decryption result:",text.hex(),tag.hex()) # b'plaibn text'
    except ValueError:
        print("Decryption failed")
    return text.hex(),tag.hex()

def decrypt_it(counter,data,tag):
    system_title ="4C4E543937343236" #Server system Title
   # system_title ="4C4E434C49454E54"#Client system Title
    iv           =bytes.fromhex(system_title + str(counter))
    Ciphering_key=bytes.fromhex("31323334353637383930313233343536")
    aad          =bytes.fromhex("3031323334353637383930313233343536")
    cipher = AES.new(Ciphering_key, AES.MODE_GCM, iv,mac_len=12,) # nonce
    cipher.update(aad)
    try:
        dec = cipher.decrypt_and_verify(bytes.fromhex(data),bytes.fromhex(tag))
        print("Decryption result:",dec.hex()) # b'plain text'
    except ValueError:
        print("Decryption failed")

def cipher_it(counter,data):
    system_title ="4C4E434C49454E54"
    #system_title ="4C4E543937343236"
    iv           =bytes.fromhex(system_title + str(counter))
    Ciphering_key=bytes.fromhex("31323334353637383930313233343536")
    aad          =bytes.fromhex("3031323334353637383930313233343536")
    cipher = AES.new(Ciphering_key, AES.MODE_GCM, iv,mac_len=12,) # nonce
    cipher.update(aad)
    if len(data)==2:
       ciphertxt,tag=data[0],data[1]
       try:
           dec = cipher.decrypt_and_verify(bytes.fromhex(ciphertxt),bytes.fromhex(tag))
       except ValueError:
           print("Decryption failed")
       return dec.hex()
    else:
       plain_text=data[0]
       try:
           ciphertst,tag = cipher.encrypt_and_digest(bytes.fromhex(plain_text))
       except ValueError:
           print("Encryption failed")
       return [ciphertst.hex(),tag.hex()]

print(cipher_it(counter123,[cipher_text123,tag123]))
#If "decrypt_it" dont work try "cipher_it(counter,[ciphertext,tag])"
