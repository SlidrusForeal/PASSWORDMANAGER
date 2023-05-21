import base64
import os
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

APP_NAME = 'PasswordManager'
passwords_dir = os.path.join(os.getenv('APPDATA'), APP_NAME)
os.makedirs(passwords_dir, exist_ok=True)
PASSWORDS_FILE = os.path.join(passwords_dir, 'oak.txt')
HINTS_FILE = os.path.join(passwords_dir, 'hints.txt')


def caesar_encrypt(plaintext, key):
    encrypted = ''
    for char in plaintext:
        if char.isalpha():
            if 'а' <= char <= 'я':
                ascii_offset = ord('а')
                alphabet_size = 32
            elif 'А' <= char <= 'Я':
                ascii_offset = ord('А')
                alphabet_size = 32
            elif 'a' <= char <= 'z':
                ascii_offset = ord('a')
                alphabet_size = 26
            elif 'A' <= char <= 'Z':
                ascii_offset = ord('A')
                alphabet_size = 26
            else:
                encrypted += char
                continue

            encrypted += chr((ord(char) - ascii_offset + key) % alphabet_size + ascii_offset)
        else:
            encrypted += char
    return encrypted


def caesar_decrypt(ciphertext, key):
    decrypted = ''
    for char in ciphertext:
        if char.isalpha():
            if 'а' <= char <= 'я':
                ascii_offset = ord('а')
                alphabet_size = 32
            elif 'А' <= char <= 'Я':
                ascii_offset = ord('А')
                alphabet_size = 32
            elif 'a' <= char <= 'z':
                ascii_offset = ord('a')
                alphabet_size = 26
            elif 'A' <= char <= 'Z':
                ascii_offset = ord('A')
                alphabet_size = 26
            else:
                decrypted += char
                continue

            decrypted += chr((ord(char) - ascii_offset - key) % alphabet_size + ascii_offset)
        else:
            decrypted += char
    return decrypted


def encrypt_base64(plaintext, key):
    encrypted_text = caesar_encrypt(plaintext, key)
    encoded_bytes = base64.b64encode(encrypted_text.encode('utf-8'))
    return encoded_bytes.decode('utf-8')


def decrypt_base64(encoded_str, key):
    decoded_bytes = base64.b64decode(encoded_str.encode('utf-8'))
    decrypted_text = decoded_bytes.decode('utf-8', errors='replace')
    decrypted_text = caesar_decrypt(decrypted_text, key)
    return decrypted_text


def save_password_gui():
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    secret_phrase = secret_phrase_entry.get()

    empty_fields = []

    if not website:
        empty_fields.append('Сайт')

    if not username:
        empty_fields.append('Имя пользователя')

    if not password:
        empty_fields.append('Пароль')

    if not secret_phrase:
        empty_fields.append('Секретная фраза')

    if empty_fields:
        messagebox.showerror('Ошибка', f'Не заполнены следующие поля: {", ".join(empty_fields)}')
        return

    key = len(secret_phrase)
    encoded_password = encrypt_base64(password, key)

    with open(PASSWORDS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{website},{username},{encoded_password}\n")

    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)


def show_passwords_gui():
    secret_phrase = secret_phrase_entry.get()
    if not secret_phrase:
        messagebox.showerror('Ошибка', 'Секретная фраза не заполнена.')
        return

    key = len(secret_phrase)
    passwords_text.delete('1.0', tk.END)
    with open(PASSWORDS_FILE, "r", encoding='utf-8') as file:
        content = file.read()
        if not content:
            messagebox.showerror('Ошибка', 'Текстовый документ с паролями пуст.')
            return
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                website, username, encoded_password = line.split(",")
            except ValueError:
                print(f"Skipping invalid line: {line}")
                continue
            decoded_password = decrypt_base64(encoded_password, key)
            passwords_text.insert(tk.END, f"Сайт: {website}\nUsername: {username}\nPassword: {decoded_password}\n\n")


def save_hint():
    secret_hint = secret_hint_entry.get()
    if not secret_hint:
        messagebox.showerror('Ошибка', 'Поле пусто')
    else:
        with open(HINTS_FILE, 'w', encoding='utf-8') as f:
            f.write(secret_hint)
        messagebox.showinfo('Подсказка к секретной фразе', 'Подсказка сохранена!')


def show_hint():
    if not os.path.exists(HINTS_FILE):
        messagebox.showinfo('Подсказка к секретной фразе', 'Подсказка не найдена.')
    else:
        with open(HINTS_FILE, 'r', encoding='utf-8') as f:
            hint = f.read()
        if hint:
            messagebox.showinfo('Подсказка к секретной фразе', hint)
        else:
            messagebox.showinfo('Подсказка к секретной фразе', 'Подсказка не найдена.')


def show_secret_phrase():
    secret_phrase = secret_phrase_entry.get()
    if not secret_phrase:
        messagebox.showerror('Ошибка', 'Секретная фраза не заполнена.')
    else:
        messagebox.showinfo('Секретная фраза', secret_phrase)


def show_password():
    password = password_entry.get()
    if not password:
        messagebox.showerror('Ошибка', 'Поле пароля не заполнено.')
    else:
        messagebox.showinfo('Пароль', password)


root = tk.Tk()
root.title('Password Manager')
icon_path = 'icon.ico'
if os.path.exists(icon_path):
    root.iconbitmap(icon_path)
custom_style = ttk.Style()
custom_style.configure("Custom.TLabel", font=("Helvetica", 12))
custom_style.configure("Custom.TEntry", font=("Helvetica", 12))
custom_style.configure("Custom.TButton", font=("Helvetica", 12))

website_label = ttk.Label(root, text='Сайт:', style="Custom.TLabel")
website_label.grid(row=0, column=0, sticky=tk.E)
website_entry = ttk.Entry(root, style="Custom.TEntry")
website_entry.grid(row=0, column=1)

username_label = ttk.Label(root, text='Имя пользователя:', style="Custom.TLabel")
username_label.grid(row=1, column=0, sticky=tk.E)

username_entry = ttk.Entry(root, style="Custom.TEntry")
username_entry.grid(row=1, column=1)

password_label = ttk.Label(root, text='Пароль:', style="Custom.TLabel")
password_label.grid(row=2, column=0, sticky=tk.E)

password_entry = ttk.Entry(root, show='*', style="Custom.TEntry")
password_entry.grid(row=2, column=1)

show_password_button = ttk.Button(root, text='Показать пароль', command=show_password, style="Custom.TButton")
show_password_button.grid(row=2, column=2)

secret_phrase_label = ttk.Label(root, text='Секретная фраза:', style="Custom.TLabel")
secret_phrase_label.grid(row=3, column=0, sticky=tk.E)

secret_phrase_entry = ttk.Entry(root, show='*', style="Custom.TEntry")
secret_phrase_entry.grid(row=3, column=1)

show_secret_phrase_button = ttk.Button(root, text='Показать фразу', command=show_secret_phrase, style="Custom.TButton")
show_secret_phrase_button.grid(row=3, column=2)

save_button = ttk.Button(root, text='Сохранить пароль', command=save_password_gui, style="Custom.TButton")
save_button.grid(row=4, column=0, columnspan=2)

show_button = ttk.Button(root, text='Показать пароли', command=show_passwords_gui, style="Custom.TButton")
show_button.grid(row=5, column=0, columnspan=2)

passwords_text = tk.Text(root, font=("Helvetica", 12))
passwords_text.grid(row=6, column=0, columnspan=3)

hint_label = ttk.Label(root, text='Подсказка к фразе:', style="Custom.TLabel")
hint_label.grid(row=7, column=0, sticky=tk.E)

hint_button = ttk.Button(root, text='Показать подсказку', command=show_hint, style="Custom.TButton")
hint_button.grid(row=7, column=1)

secret_hint_entry = ttk.Entry(root, show='*', style="Custom.TEntry")
secret_hint_entry.grid(row=7, column=2)

save_hint_button = ttk.Button(root, text='Сохранить подсказку', command=save_hint, style="Custom.TButton")
save_hint_button.grid(row=8, column=0, columnspan=2)

root.mainloop()
