import tkinter as tk
from tkinter import filedialog, messagebox
import os
import analyzer

# ------------------ FUNCTIONS ------------------

def select_app_folder():
    folder = filedialog.askdirectory(title="Select Decompiled APK Folder")

    if not folder:
        return

    manifest_path = os.path.join(folder, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        messagebox.showerror(
            "Error",
            "AndroidManifest.xml not found.\nPlease select a valid decompiled APK folder."
        )
        return

    try:
        permissions = analyzer.extract_permissions(manifest_path)
        score = analyzer.calculate_risk_score(permissions)
        final_verdict = analyzer.verdict(score)
    except Exception as e:
        messagebox.showerror("Analysis Error", str(e))
        return

    output_text.config(state="normal")
    output_text.delete("1.0", tk.END)

    output_text.insert(tk.END, f"📱 App Folder: {os.path.basename(folder)}\n\n")
    output_text.insert(tk.END, "🔐 Permissions Found:\n")

    for p in permissions:
        output_text.insert(tk.END, f"  • {p}\n")

    output_text.insert(tk.END, f"\n📊 Risk Score: {score}\n")
    output_text.insert(tk.END, f"⚠ Verdict: {final_verdict}\n")

    # Color-code verdict
    if "CRITICAL" in final_verdict or "HIGH" in final_verdict:
        verdict_label.config(text=final_verdict, fg="red")
    elif "MEDIUM" in final_verdict:
        verdict_label.config(text=final_verdict, fg="orange")
    else:
        verdict_label.config(text=final_verdict, fg="green")

    output_text.config(state="disabled")

# ------------------ UI SETUP ------------------

root = tk.Tk()
root.title("Application Permission Misuse Detection Tool")
root.geometry("750x600")
root.configure(bg="#f2f2f2")
root.resizable(False, False)

# Title
title_label = tk.Label(
    root,
    text="Application Permission Misuse Detection Tool",
    font=("Segoe UI", 18, "bold"),
    bg="#f2f2f2"
)
title_label.pack(pady=15)

# Button
select_button = tk.Button(
    root,
    text="Select Decompiled APK Folder",
    font=("Segoe UI", 12, "bold"),
    bg="#0078D7",
    fg="white",
    padx=20,
    pady=10,
    command=select_app_folder
)
select_button.pack(pady=10)

# Verdict Label
verdict_label = tk.Label(
    root,
    text="",
    font=("Segoe UI", 14, "bold"),
    bg="#f2f2f2"
)
verdict_label.pack(pady=10)

# Output Frame
frame = tk.Frame(root)
frame.pack(padx=20, pady=10, fill="both", expand=True)

scrollbar = tk.Scrollbar(frame)
scrollbar.pack(side="right", fill="y")

output_text = tk.Text(
    frame,
    font=("Consolas", 10),
    wrap="word",
    yscrollcommand=scrollbar.set,
    state="disabled"
)
output_text.pack(fill="both", expand=True)

scrollbar.config(command=output_text.yview)

# Footer
footer = tk.Label(
    root,
    text="Static Android Permission Analysis | Cybersecurity Project",
    font=("Segoe UI", 9),
    bg="#f2f2f2"
)
footer.pack(pady=8)

root.mainloop()
