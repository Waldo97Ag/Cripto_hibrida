from tkinter import *
from tkinter import messagebox, filedialog
from tkinter import ttk
import tkinter as tk
import os, sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15

import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

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
        
        combo_sel=combo.get()
        message_sent = message.get()
        if combo_sel == "Cipher":
            message_sent = message.get()   #Mensaje que Alicia manda
            message_file = open("message_s.txt", "w",encoding='utf-8')
            with open('message.txt') as f:       
                message_file.write(message_sent) #Escribir mensaje a archivo
                message_file.close()
            message_as_bytes = read_file_content_as_bytes('message.txt')
            encrypt_AES_CBC(message_as_bytes)   

        elif combo_sel == "Decipher":
            pass
        elif combo_sel == "Signature":
            pass

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
        content_bytes = str.encode(content)

    return content_bytes


def encrypt_AES_CBC(data):
    
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    print(result)


# def generate_digest(message):
#     h = SHA1.new()
#     h.update(message)

#     return h.hexdigest()

# def generate_signature(message_to_sign):
#     print("Generating Signature")
#     key = RSA.import_key(open('private_candy.pem').read())
#     message_to_sign = message_to_sign.encode("ISO-8859-1")
#     h = SHA256.new(message_to_sign)
#     signature = pkcs1_15.new(key).sign(h)
#     message_signed = signature.decode("ISO-8859-1")

#     signed_file = open("message_s.txt", "w",encoding='utf-8')
#     with open('strawberry.txt') as f:
#         message_strawberry = f.readlines()
#         message_strawberry = ''.join(message_strawberry)
#     signed_file.write(message_strawberry)
#     signed_file.write("\n\n")
#     signed_file.write(message_signed)
#     signed_file.close()



#     return signature

# def verify_signature(message, signature_v):
#     key = RSA.import_key(open('public_alice.pem').read())
#     message = message.encode("ISO-8859-1")
#     h = SHA256.new(message)
#     try:
#         pkcs1_15.new(key).verify(h, signature_v)
#         messagebox.showinfo("Success","Message verified correctly valid signature")
#     except (ValueError, TypeError) as e:
#         messagebox.showinfo("Error","Signature not valid")

raiz.mainloop()
