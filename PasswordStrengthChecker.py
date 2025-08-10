import tkinter as tk
from tkinter import messagebox
from password_checker import PasswordStrengthChecker, format_time  # Make sure this matches your filename

class PasswordApp:
    def __init__(self, root):
        self.checker = PasswordStrengthChecker()
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("600x550")
        self.root.configure(bg="#f4f4f4")

        # Title label
        self.title_label = tk.Label(
            root, text="Password Strength Checker",
            font=("Helvetica", 18, "bold"),
            bg="#f4f4f4", fg="#333"
        )
        self.title_label.pack(pady=20)

        # Password entry
        self.entry = tk.Entry(
            root, width=30, show="*",
            font=("Helvetica", 14),
            relief="solid", bd=1
        )
        self.entry.pack(pady=10)

        # Check button
        self.check_btn = tk.Button(
            root, text="Check Strength",
            command=self.analyze_password,
            font=("Helvetica", 12),
            bg="#007BFF", fg="white",
            activebackground="#0056b3", activeforeground="white",
            relief="flat", padx=10, pady=5
        )
        self.check_btn.pack(pady=10)

        # Results output box
        self.result_box = tk.Text(
            root, width=70, height=20,
            wrap="word", font=("Helvetica", 10),
            bg="#ffffff", fg="#222", relief="solid", bd=1
        )
        self.result_box.pack(pady=15)

        # Footer
        self.footer = tk.Label(
            root, text="Developed by Dev",
            font=("Helvetica", 9),
            bg="#f4f4f4", fg="#888"
        )
        self.footer.pack(pady=5)

    def analyze_password(self):
        password = self.entry.get().strip()
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password.")
            return

        analysis = self.checker.analyze_password_strength(password)
        crack_time = self.checker.estimate_crack_time(password)

        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, "Password Analysis:\n")
        self.result_box.insert(tk.END, f"- Strength: {analysis['strength']} (Score: {analysis['score']}/8)\n")
        self.result_box.insert(tk.END, f"- Length: {analysis['length']} characters\n")
        self.result_box.insert(tk.END, f"- Includes Lowercase: {analysis['has_lowercase']}\n")
        self.result_box.insert(tk.END, f"- Includes Uppercase: {analysis['has_uppercase']}\n")
        self.result_box.insert(tk.END, f"- Includes Digits:    {analysis['has_digits']}\n")
        self.result_box.insert(tk.END, f"- Includes Special:   {analysis['has_special']}\n")

        if analysis['feedback']:
            self.result_box.insert(tk.END, "\nRecommendations:\n")
            for feedback in analysis['feedback']:
                self.result_box.insert(tk.END, f"  • {feedback}\n")

        self.result_box.insert(tk.END, "\nEstimated Crack Time:\n")
        self.result_box.insert(tk.END, f"- Charset Size: {crack_time['charset_size']}\n")
        self.result_box.insert(tk.END, f"- Total Combinations: {crack_time['combinations']:,}\n")
        self.result_box.insert(tk.END, f"- Estimated Time: {format_time(crack_time['seconds'])}\n")

def run_app():
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()

if __name__ == "__main__":
    run_app()
