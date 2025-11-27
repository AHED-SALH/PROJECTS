import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os


def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    priv_file = filedialog.asksaveasfilename(defaultextension=".pem", title="  savea the private key")
    pub_file = filedialog.asksaveasfilename(defaultextension=".pem", title=" savea the public key")

    if priv_file and pub_file:
        with open(priv_file, "wb") as f:
            f.write(private_key)
        with open(pub_file, "wb") as f:
            f.write(public_key)
        messagebox.showinfo("successfully ", f" keys crearted and savea \n {os.getcwd()}")
    else:
        messagebox.showwarning("erral", " keys are not savead ")



def encrypt():
    msg = text_input.get("1.0", tk.END).strip()
    if not msg:
        messagebox.showwarning("erral ", "enter the masgea first ")
        return

    pub_file = filedialog.askopenfilename(title="select the public key file ", filetypes=[("PEM files", "*.pem")])
    if not pub_file:
        return

    with open(pub_file, "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(msg.encode())

    save_file = filedialog.asksaveasfilename(defaultextension=".bin", title="savea the cipherthext")
    if save_file:
        with open(save_file, "wb") as f:
            f.write(ciphertext)
        messagebox.showinfo("نجاح", f" تم التشفير وحفظه في:\n{save_file}")



def decrypt():
    priv_file = filedialog.askopenfilename(title="select private file key", filetypes=[("PEM files", "*.pem")])
    ci_file = filedialog.askopenfilename(title="اختر ملف النص المشفر", filetypes=[("BIN files", "*.bin")])

    if not priv_file or not ci_file:
        return

    with open(priv_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(ci_file, "rb") as f:
        ciphertext = f.read()

    decipher = PKCS1_OAEP.new(private_key)
    plaintext = decipher.decrypt(ciphertext).decode()

    messagebox.showinfo(" الرسالة المفكوك تشفيرها", plaintext)

    save_file = filedialog.asksaveasfilename(defaultextension=".txt", title="حفظ النص المفكوك")
    if save_file:
        with open(save_file, "wb") as f:
            f.write(plaintext.encode("utf-8"))
        messagebox.showinfo("نجاح", f" تم حفظ النص المفكوك في:\n{save_file}")


root = tk.Tk()
root.title("RSA Encryption/Decryption")
root.geometry("450x350")

tk.Label(root, text=" enter the message :", font=("Arial", 12)).pack(pady=5)
text_input = tk.Text(root, height=6, width=50)
text_input.pack(pady=5)

tk.Button(root, text=" keys generation ", width=20, command=generate_keys).pack(pady=5)
tk.Button(root, text=" Encryption" , width=20, command=encrypt).pack(pady=5)
tk.Button(root, text=" Decryption ", width=20, command=decrypt).pack(pady=5)

root.mainloop()
