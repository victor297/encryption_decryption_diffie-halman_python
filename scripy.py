import pyAesCrypt
buffersize = 64 * 1024 # 64kb size of file
#get password from user input
password = input("Enter password to encrypt or decrypt your file : ")
# get option from user input to encrypt by typing E,e or D,d to decrypt
EorD = str(input("Enter E to encrypt file or D to decrypt it : ")).upper ()
if(EorD == "E"):
    try:
      #ecrypt file
      pyAesCrypt.encryptFile("vee.png","vee.png.vic", password,buffersize)
      print("file encrypted successfully")
    except EOFError as err:
       print(err)
elif(EorD== "D"):
    #decrypt file
    try:
        pyAesCrypt.decryptFile("vee.png.vic", "veeout.png", password,buffersize)
        print("file decrypted successfully")
    except EOFError as err:
        print(err)
else:
    print("Please choose E,e OR D,d 112")