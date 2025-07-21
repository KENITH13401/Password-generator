import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import re
import pyperclip

def generate_password():
    try:
        length = int(length_entry.get())
        if length < 4:
            messagebox.showerror("Error", "Minimum length is 4")
            return
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number")
        return

    chars = ""
    if lowercase_var.get():
        chars += string.ascii_lowercase
    if uppercase_var.get():
        chars += string.ascii_uppercase
    if digits_var.get():
        chars += string.digits
    if special_var.get():
        chars += string.punctuation

    if not chars:
        messagebox.showwarning("Error", "Select at least one character type!")
        return

    password = ''.join(random.choice(chars) for _ in range(length))
    password_var.set(password)
    evaluate_strength(password)

def evaluate_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1

    strength_bar['value'] = score * 20

    if score == 5:
        strength_text.config(text="Strength: Strong", foreground="lightgreen")
        strength_bar.configure(style="green.Horizontal.TProgressbar")
    elif score >= 3:
        strength_text.config(text="Strength: Medium", foreground="orange")
        strength_bar.configure(style="orange.Horizontal.TProgressbar")
    else:
        strength_text.config(text="Strength: Weak", foreground="red")
        strength_bar.configure(style="red.Horizontal.TProgressbar")

def copy_password():
    pwd = password_var.get()
    if pwd:
        pyperclip.copy(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

# ------------------ GUI SETUP ---------------------------
root = tk.Tk()
root.title("🔐 Password Generator Pro")
root.geometry("420x430")
root.configure(bg="#1e1e1e")
root.resizable(False, False)

# ------------------ STYLE CONFIG ------------------------
style = ttk.Style()
style.theme_use("clam")
style.configure("TLabel", background="#1e1e1e", foreground="white", font=("Arial", 10))
style.configure("TCheckbutton", background="#1e1e1e", foreground="white")
style.configure("TButton", font=("Arial", 10), padding=6)
style.configure("TEntry", font=("Arial", 11))
style.configure("green.Horizontal.TProgressbar", troughcolor='#1e1e1e', background='lightgreen')
style.configure("orange.Horizontal.TProgressbar", troughcolor='#1e1e1e', background='orange')
style.configure("red.Horizontal.TProgressbar", troughcolor='#1e1e1e', background='red')

# ------------------ UI ELEMENTS -------------------------
ttk.Label(root, text="Password Length:").pack(pady=5)
length_entry = ttk.Entry(root)
length_entry.pack()
length_entry.insert(0, "12")

# Checkbuttons
lowercase_var = tk.BooleanVar(value=True)
uppercase_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
special_var = tk.BooleanVar(value=True)

ttk.Checkbutton(root, text="Include Lowercase Letters", variable=lowercase_var).pack(pady=2)
ttk.Checkbutton(root, text="Include Uppercase Letters", variable=uppercase_var).pack(pady=2)
ttk.Checkbutton(root, text="Include Numbers", variable=digits_var).pack(pady=2)
ttk.Checkbutton(root, text="Include Special Characters", variable=special_var).pack(pady=2)

ttk.Button(root, text="Generate Password", command=generate_password).pack(pady=10)

password_var = tk.StringVar()
ttk.Entry(root, textvariable=password_var, font=("Arial", 12), width=35).pack(pady=5)

ttk.Button(root, text="Copy to Clipboard", command=copy_password).pack(pady=5)

strength_text = ttk.Label(root, text="Strength: ", font=("Arial", 11))
strength_text.pack(pady=5)

strength_bar = ttk.Progressbar(root, length=250, mode='determinate')
strength_bar.pack(pady=5)

root.mainloop()
