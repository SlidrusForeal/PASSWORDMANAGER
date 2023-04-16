from tkinter import *
from tkinter import messagebox
import base64

PASSWORDS_FILE = 'passwords.txt'

def encrypt_base64(plaintext):
    # Зашифровать текст с помощью кодирования base64
    encoded_bytes = base64.b64encode(plaintext.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

def decrypt_base64(encoded_str):
    # Расшифровать текст с помощью декодирования base64
    decoded_bytes = base64.b64decode(encoded_str.encode('utf-8'))
    return decoded_bytes.decode('utf-8')


def save_password_gui():
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    secret_phrase = secret_phrase_entry.get()

    # Зашифровать пароль с помощью кодирования base64
    encoded_password = encrypt_base64(password)

    with open(PASSWORDS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{website},{username},{encoded_password}\n")

    website_entry.delete(0, END)
    username_entry.delete(0, END)
    password_entry.delete(0, END)


def show_passwords_gui():
    secret_phrase = secret_phrase_entry.get()
    passwords_text.delete('1.0', END)
    with open(PASSWORDS_FILE, "r", encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                website, username, encoded_password = line.split(",")
            except ValueError:
                print(f"Пропускаю неверную строку: {line}")
                continue

            # Расшифровать пароль с помощью декодирования base64
            decoded_password = decrypt_base64(encoded_password)

            # Добавить расшифрованный пароль в виджет текста паролей
            passwords_text.insert(END, f"Сайт: {website}\nИмя пользователя: {username}\nПароль: {decoded_password}\n\n")


root = Tk()
root.title('Менеджер паролей')

website_label = Label(root, text='Сайт:')
website_label.pack()

website_entry = Entry(root)
website_entry.pack()

username_label = Label(root, text='Имя пользователя:')
username_label.pack()

username_entry = Entry(root)
username_entry.pack()

password_label = Label(root, text='Пароль:')
password_label.pack()

password_entry = Entry(root, show='*')
password_entry.pack()

secret_phrase_label = Label(root, text='Секретная фраза:')
secret_phrase_label.pack()

secret_phrase_entry = Entry(root, show='*')
secret_phrase_entry.pack()

save_button = Button(root, text='Сохранить пароль', command=save_password_gui)
save_button.pack()

show_button = Button(root, text='Показать пароли', command=show_passwords_gui)
show_button.pack()

passwords_text = Text(root)
passwords_text.pack()

root.mainloop()
