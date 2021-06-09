from tkinter import *
from tkinter import messagebox, filedialog
from tkinter import ttk
import tkinter as tk
import os, sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

iv_ct, key = None, None


raiz=Tk()
raiz.title("Hybrid Cryptography")
raiz.resizable(0,0)

raiz.geometry("500x250")
raiz.config(bg="cyan")

myFrame=Frame()
myFrame.pack(side="top")
myFrame.config(bg="white")
#myFrame.config(width="350", height="350")

#Logo ESCOM
imagen=tk.PhotoImage(file="logoescom.png")
imagen_sub=imagen.subsample(12)
widget=ttk.Label(image=imagen_sub)
widget.place(x=5,y=5)

#Logo IPN
imageni=tk.PhotoImage(file="ipn.png")
imageni_sub=imageni.subsample(15)
widgeti=ttk.Label(image=imageni_sub)
widgeti.place(x=400,y=5)

text = Label(text="Escuela Superior de Computo\n Oswaldo Aguilar Martinez \n Miguel Angel Arevalo Andrade")
text.place(x=125,y=7)

process_label=Label(raiz, text = "Process")
process_label.place(x=170,y=100)
combo=ttk.Combobox(raiz)
combo.place(x=230,y=100)
combo['values']=('Cipher','Decipher','Signature','Verification','Cipher & Signature','Decipher & Verification')

label_message=Label(raiz, text = "Message:")
label_message.place(x=180,y=140)
message = ttk.Entry(raiz)
# Posicionarla en la ventana.
message.place(x=250, y=140)

def generar_llaves():
    key_alice = RSA.generate(2048)
    private_key_alice = key_alice.export_key()
    file_out = open("private_alice.pem", "wb")
    file_out.write(private_key_alice)
    file_out.close()

    public_key_alice = key_alice.publickey().export_key()
    file_out = open("public_alice.pem", "wb")
    file_out.write(public_key_alice)
    file_out.close()

    key_bob = RSA.generate(2048)
    private_key_bob = key_bob.export_key()
    file_out = open("private_bob.pem", "wb")
    file_out.write(private_key_bob)
    file_out.close()

    public_key_bob = key_bob.publickey().export_key()
    file_out = open("public_bob.pem", "wb")
    file_out.write(public_key_bob)
    file_out.close()


def seleccionar_funcion():
        global iv_ct, key
        combo_sel=combo.get()

        if combo_sel == "Cipher":
            message_sent = message.get()   #Mensaje que Alicia manda
            message_file = open("message.txt", "w",encoding='ISO-8859-1')
            with open('message.txt') as f:
                message_file.write(message_sent) #Escribir mensaje a archivo
                message_file.close()
            message_as_bytes = read_file_content_as_bytes('message.txt')
            iv_ct, key = encrypt_AES_CBC(message_as_bytes)
            cipher_AES_key_with_RSA(key)

        elif combo_sel == "Decipher":
            key_session=decipher_AES_key_with_RSA()
            decrypt_AES_CBC(iv_ct, key_session)

        elif combo_sel == "Signature":
            message_sent = message.get()   #Mensaje que Alicia manda
            encoded_string = message_sent.encode('ISO-8859-1')
            message_to_sign = generate_digest(encoded_string)
            signature_v = generate_signature(message_to_sign)

        elif combo_sel == "Verification":
            pass

        elif combo_sel == "Cipher & Signature":
            message_sent = message.get()

        elif combo_sel == "Decipher & Verification":
            pass


        else:
            messagebox.showinfo("Error ","You must select an option")

def abrirArchivo_a_Usar():
    raiz.archivo=filedialog.askopenfilename(initialdir="C:",title = "Select a txt file to sign or to verify",filetypes=(("txt files","*.txt"),("all files","*.*")))

def seleccionar_llave():
    raiz.llave=filedialog.askopenfilename(initialdir="C:",title = "Select private or public key",filetypes=(("pem files","*.pem"),("all files","*.*")))

abrir=Button(raiz, text="Select File",command=abrirArchivo_a_Usar)
abrir.place(x=50,y=100)

pubkey=Button(raiz, text="Select Key",command=seleccionar_llave)
pubkey.place(x=50,y=140)


start=Button(raiz, text="Start process",command=seleccionar_funcion)
start.place(x=50,y=180)

sel=Button(raiz, text="Generate Keys",command=generar_llaves)
sel.place(x=200,y=180)

def read_file_content_as_bytes(file):
    with open(file) as f:
        content = f.readlines()
        content = ''.join(content)
        content_bytes = str.encode(content)

    return content_bytes


def encrypt_AES_CBC(data):

    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('ISO-8859-1')
    ct = b64encode(ct_bytes).decode('ISO-8859-1')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)
    return result, key #Esta madre es la que se cifra con RSA

def decrypt_AES_CBC(json_input,key): #Recibe vector iv y texto cifrado
    try:
        b64 = json.loads(json_input)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt1 = unpad(cipher.decrypt(ct), AES.block_size)
        pt=pt1.decode('ISO-8859-1')
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")


def cipher_AES_key_with_RSA(data):
    file_out = open("message.txt", "ab")

    recipient_key = RSA.import_key(open("public_bob.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    file_out.write(bytes("\nFIN", 'ISO-8859-1'))
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    #print(enc_session_key)
    #print(cipher_aes.nonce)
    #print(tag)
    #print(ciphertext)
    file_out.close()

def decipher_AES_key_with_RSA():
    file_in1 = open("message.txt", "rb")
    f=file_in1.read()
    #file_in=file_in1.decode('ISO-8859-1')
    #file_in = ''.join(file_in)
    file_in=f.decode('ISO-8859-1')
    #file_in=bytes(f,'ISO-8859-1')
    mensaje,llave_AES1,Firma = file_in.split("\nFIN")
    file_in1.close()
    llave_AES=llave_AES1[:-1:]
    file_out = open("message1.txt", "wb")
    file_out.write(bytes(llave_AES, 'ISO-8859-1'))
    file_out.close()
    private_key = RSA.import_key(open("private_bob.pem").read())
        #Falta verificar si se divide bien el archivo en 3 con el doble \n\n como separador y trabajar
    #con la parte de enmedio que es la que se debe descifrar nada más
    key_in = open("message1.txt", "rb")
    enc_session_key, nonce, tag, ciphertext = \
        [ key_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    #print(enc_session_key.decode('ISO-8859-1'))
    #print(enc_session_key)
    #print(nonce)
    #print(tag)
    #print(ciphertext)
    #print(tag)
    #print(ciphertext)
# Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    #print(data.decode("ISO-8859-1"))
    return data
def generate_digest(message):
    h = SHA1.new()
    h.update(message)

    return h.hexdigest()

def generate_signature(message_to_sign):
    print("Generating Signature")
    key = RSA.import_key(open('private_alice.pem').read())
    message_to_sign = message_to_sign.encode("ISO-8859-1")
    h = SHA256.new(message_to_sign)
    signature = pkcs1_15.new(key).sign(h)
    message_signed = signature.decode("ISO-8859-1")

    signed_file = open("message.txt", "a",encoding='ISO-8859-1') #Concatenando la firma después de dos saltos de linea
    signed_file.write("\nFIN")
    signed_file.write(message_signed)
    signed_file.close()

    return signature

def verify_signature(message, signature_v):
    key = RSA.import_key(open('public_alice.pem').read())
    message = message.encode("ISO-8859-1")
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature_v)
        messagebox.showinfo("Success","Message verified correctly valid signature")
    except (ValueError, TypeError) as e:
        messagebox.showinfo("Error","Signature not valid")

raiz.mainloop()
