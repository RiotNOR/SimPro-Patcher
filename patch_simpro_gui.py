# Supports: default (0x90000000), resizing (0x90050000), native frame (0x00CF0000)

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False


class SimProPatcherGUI:
    def __init__(self, root):
        self.root = root
        self.root.geometry("500x450")
        self.root.resizable(True, True)
        
        self.selected_path = tk.StringVar()
        self.patch_option = tk.StringVar(value="default")
        
        self.create_widgets()
        
        title = "SimPro Patcher"
        if self.is_admin():
            title += " (Administrator)"
        self.root.title(title)
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(main_frame, text="Select SimPro.exe:", 
                 font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        
        path_frame = ttk.Frame(main_frame)
        path_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        path_frame.columnconfigure(0, weight=1)
        
        self.path_entry = ttk.Entry(path_frame, textvariable=self.selected_path, width=40)
        self.path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Button(path_frame, text="Browse", 
                  command=self.browse_file).grid(row=0, column=1)
        
        ttk.Label(main_frame, text="Patch Option:", 
                 font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=(0, 10))
        
        patch_frame = ttk.Frame(main_frame)
        patch_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        
        ttk.Radiobutton(patch_frame, text="Default - no changes (0x90000000)", 
                       variable=self.patch_option, value="default").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Radiobutton(patch_frame, text="Enable resizing only (0x90050000)", 
                       variable=self.patch_option, value="resize").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Radiobutton(patch_frame, text="Show native window frame (0x00CF0000)", 
                       variable=self.patch_option, value="native").grid(row=2, column=0, sticky=tk.W, pady=2)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, pady=15)
        ttk.Button(button_frame, text="Patch Selected File", 
                  command=self.patch_file).pack()
        
        ttk.Label(main_frame, text="Status:", 
                 font=("Arial", 10, "bold")).grid(row=5, column=0, sticky=tk.W, pady=(10, 5))
        
        text_frame = ttk.Frame(main_frame)
        text_frame.grid(row=6, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        
        self.result_text = tk.Text(text_frame, height=6, wrap=tk.WORD, font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        admin_status = " (Administrator)" if self.is_admin() else " (Standard User)"
        self.log(f"SimPro Patcher ready{admin_status}")
        
        if not self.is_admin():
            self.log("Note: Running as standard user - may need admin rights for protected folders")
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select SimPro.exe",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filename:
            self.selected_path.set(filename)
            self.log(f"Selected file: {os.path.basename(filename)}")
    
    def log(self, message):
        self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)
        self.root.update_idletasks()
        
    def clear_log(self):
        self.result_text.delete(1.0, tk.END)
    
    def is_admin(self) -> bool:
        if not HAS_CTYPES or os.name != 'nt':
            return False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def check_write_permissions(self, file_path: str) -> bool:
        try:
            directory = os.path.dirname(file_path)
            temp_file = os.path.join(directory, '.simpro_patcher_test_write')
            
            with open(temp_file, 'w') as f:
                f.write('test')
            
            os.remove(temp_file)
            return True
            
        except (PermissionError, OSError) as e:
            self.log(f"[-] Write permission denied: {str(e)}")
            return False
            
    def get_patch_bytes(self):
        if self.patch_option.get() == "default":
            return bytes.fromhex("B8 00 00 00 90")
        elif self.patch_option.get() == "resize":
            return bytes.fromhex("B8 00 00 05 90")
        else:
            return bytes.fromhex("B8 00 0F CF 00")
            
    def get_patch_description(self):
        if self.patch_option.get() == "default":
            return "Restore default behavior (-> 0x90000000)"
        elif self.patch_option.get() == "resize":
            return "Enable resizing only (-> 0x90050000)"
        else:
            return "Show native window frame (-> 0x00CF0000)"
            
    def find_all(self, data: bytes, pat: bytes) -> list[int]:
        out = []
        start = 0
        while True:
            i = data.find(pat, start)
            if i < 0:
                return out
            out.append(i)
            start = i + 1

    def patch_with_signature(self, exe_path: str) -> bool:
        try:
            self.log(f"Starting patch process...")
            self.log(f"Loading file: {os.path.basename(exe_path)}")
            
            with open(exe_path, "rb") as f:
                blob = f.read()

            self.log("Searching for signature...")
            
            prefix_pattern = bytes.fromhex("83 F8 02 0F 44 F1")  # cmp eax,2; cmovz esi,ecx
            suffix_pattern = bytes.fromhex("80 7F 25 00 0F 44 F0")  # cmp byte ptr [rdi+25h],0; cmovz esi,eax
            
            hits = []
            prefix_hits = self.find_all(blob, prefix_pattern)
            
            for prefix_pos in prefix_hits:
                mov_pos = prefix_pos + len(prefix_pattern)
                if mov_pos + 5 + len(suffix_pattern) <= len(blob):
                    if blob[mov_pos] == 0xB8:  # MOV EAX, imm32
                        suffix_pos = mov_pos + 5
                        if blob[suffix_pos:suffix_pos + len(suffix_pattern)] == suffix_pattern:
                            hits.append(prefix_pos)
                            current_value = int.from_bytes(blob[mov_pos + 1:mov_pos + 5], 'little')
                            self.log(f"Found MOV EAX at offset 0x{mov_pos:X} with value 0x{current_value:08X}")

            if not hits:
                self.log("[-] Signature pattern not found in file")
                messagebox.showerror("Error", "Signature pattern not found in the selected file. This may not be a compatible SimPro.exe.")
                return False

            if len(hits) > 1:
                self.log(f"[!] Multiple matches found ({len(hits)}). Using first match.")

            hit = hits[0]
            mov_off = hit + 6
            mov_bytes = blob[mov_off:mov_off + 5]
            
            current_value = int.from_bytes(mov_bytes[1:5], 'little')
            self.log(f"[+] Current value: 0x{current_value:08X}")

            patched_mov = self.get_patch_bytes()
            patch_desc = self.get_patch_description()
            
            target_value = int.from_bytes(patched_mov[1:5], 'little')
            if current_value == target_value:
                self.log(f"[!] File already has target value 0x{target_value:08X}")
                messagebox.showinfo("Info", f"File is already patched to the selected value (0x{target_value:08X})")
                return True

            self.log(f"Applying patch: {patch_desc}")

            bak_path = exe_path + ".bak"
            if os.path.exists(bak_path):
                os.remove(bak_path)
            os.replace(exe_path, bak_path)
            
            self.log(f"Backup created: {os.path.basename(bak_path)}")

            patched = bytearray(blob)
            patched[mov_off:mov_off + 5] = patched_mov

            with open(exe_path, "wb") as f:
                f.write(patched)

            self.log(f"[+] Changed 0x{current_value:08X} -> 0x{target_value:08X}")
            self.log("[+] Patch completed successfully!")
            messagebox.showinfo("Success", f"Patch applied successfully!\n\n{patch_desc}\n\nBackup saved as: {os.path.basename(bak_path)}")
            return True

        except Exception as e:
            self.log(f"[-] Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to patch file: {str(e)}")
            return False

    def patch_file(self):
        path = self.selected_path.get().strip()
        if not path:
            messagebox.showerror("Error", "Please select a file first")
            return
            
        if not os.path.isfile(path):
            messagebox.showerror("Error", "Selected path is not a file")
            return
            
        if not path.lower().endswith('.exe'):
            messagebox.showwarning("Warning", "Selected file is not an executable (.exe)")
            return
        
        self.clear_log()
        self.log("=" * 50)
        self.log(f"Patching: {os.path.basename(path)}")
        self.log(f"Option: {self.get_patch_description()}")
        self.log("=" * 50)
        
        self.log("Checking write permissions...")
        if not self.check_write_permissions(path):
            directory = os.path.dirname(path)
            
            running_as_admin = self.is_admin()
            
            if running_as_admin:
                error_msg = (
                    f"Write permission denied to folder:\n{directory}\n\n"
                    "Even though you're running as administrator, the folder might have "
                    "special restrictions or the file might be in use.\n\n"
                    "Solutions:\n"
                    "• Make sure SimPro.exe is not currently running\n"
                    "• Try moving SimPro.exe to a user folder temporarily\n"
                    "• Check folder permissions manually"
                )
            else:
                error_msg = (
                    f"Write permission denied to folder:\n{directory}\n\n"
                    "This usually happens when the game is installed in a protected location "
                    "(like Program Files).\n\n"
                    "Solutions:\n"
                    "• RIGHT-CLICK this patcher and select 'Run as administrator'\n"
                    "• Or move SimPro.exe to a user folder temporarily\n"

                )
                
            messagebox.showerror("Permission Error", error_msg)
            return
            
        self.log("[+] Write permissions OK")
        self.patch_with_signature(path)


def main():
    root = tk.Tk()
    
    try:
        root.wm_attributes('-toolwindow', True)
        root.wm_attributes('-toolwindow', False)
    except:
        pass
    
    app = SimProPatcherGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
