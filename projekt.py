from tkinter import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
KEY = b'kawusiakawusia<3'

def sha1(text):
    sha = hashlib.sha1(text.encode('utf-8'))
    return sha.hexdigest()

def sha2(text):
    sha = hashlib.sha256(text.encode('utf-8'))
    return sha.hexdigest()

def md5(text):
    md5 = hashlib.md5(text.encode('utf-8'))
    return md5.hexdigest()

def szyfruj_AES(message):
    cipher = AES.new(KEY,AES.MODE_ECB)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    return encoded_ciphertext

def odszyfruj_AES():
    if var.get() != "opcja 4":
        window2 = Tk()
        window2.title("Ostrzeżenie")
        window2.geometry("600x100")
        window2.configure(bg = "light gray")
        Label(window2, text="""Szyfr ten jest jednokierunkowym algorytmem kryptograficznym,
        co oznacza, że nie można go odwrócić ani odszyfrować,
        aby uzyskać pierwotne dane.""",bg = "light gray", fg="black",font=("Yu Gothic UI Light",15)).pack()
        window2.mainloop()
    else:
        cipher = AES.new(KEY, AES.MODE_ECB)
        decoded_ciphertext = base64.b64decode(T1.get("1.0", END).strip())
        decrypted_message = cipher.decrypt(decoded_ciphertext)
        unpadded_message = unpad(decrypted_message, AES.block_size)
        T2.delete("1.0", END)
        T2.insert("1.0", unpadded_message.decode('utf-8'))

def szyfruj():
    text = T1.get("1.0", END).strip()
    if var.get() == "opcja 1":
        T2.delete("1.0", END)
        T2.insert("1.0", sha1(text))
    elif var.get() == "opcja 2":
        T2.delete("1.0", END)
        T2.insert("1.0", sha2(text))
    elif var.get() == "opcja 3":
        T2.delete("1.0", END)
        T2.insert("1.0", md5(text))
    elif var.get() == "opcja 4":
        T2.delete("1.0", END)
        T2.insert("1.0", szyfruj_AES(text))

def zapis():
    zapisz = T2.get("1.0", END).strip()
    with open("tajne.txt", "w") as f:
        f.write(zapisz)

window = Tk()
window.title("Projekt")
window.geometry("700x500")
window.configure(bg = "light gray")
Label(window, text="Wybierz szyfr:",bg = "light gray", fg="black",font=("Yu Gothic UI Light",15)).place(x=280, y=15)
var = StringVar()
rb1 = Radiobutton(window, text="SHA-128", variable=var, value="opcja 1", font=("Yu Gothic UI Light",15), height = 1, width = 10, background = "light gray", indicatoron=0).place(x=115,y=65)
rb2 = Radiobutton(window, text="SHA-256", variable=var, value="opcja 2", font=("Yu Gothic UI Light",15), height = 1, width = 10, background = "light gray", indicatoron=0).place(x=230,y=65)
rb3 = Radiobutton(window, text="MD5", variable=var, value="opcja 3", font=("Yu Gothic UI Light",15), height = 1, width = 10, background = "light gray", indicatoron=0).place(x=345,y=65)
rb4 = Radiobutton(window, text="AES-128", variable=var, value="opcja 4", font=("Yu Gothic UI Light",15), height = 1, width = 10, background = "light gray", indicatoron=0).place(x=460,y=65)
Label(window,text="Wpisz tekst:",bg = "light gray", fg="black",font=("Yu Gothic UI Light",15)).place(x=280, y=120)
T1 = Text(window, bg = "white", fg="black", height = 3, width = 46, font=("Yu Gothic UI Light",15), exportselection=False)
T1.place(x=115,y=160)
przycisk1 = Button(window, text = "Zaszyfruj",activebackground = "dark gray",activeforeground = "black",font=("Yu Gothic UI Light",15), command = szyfruj)
przycisk1.place(x=250,y=250)
przycisk2 = Button(window, text = "Odszyfruj",activebackground = "dark gray",activeforeground = "black",font=("Yu Gothic UI Light",15), command = odszyfruj_AES)
przycisk2.place(x=350,y=250)
T2 = Text(window, bg = "white", fg="black", height = 3, width = 46, font=("Yu Gothic UI Light",15), exportselection=False)
T2.place(x=115,y=310)
Button(window, text = "Zapisz do pliku .txt",activebackground = "dark gray",activeforeground = "black",font=("Yu Gothic UI Light",15), command = zapis).place(x=250,y=400)
window.mainloop()
