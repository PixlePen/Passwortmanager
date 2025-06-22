import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import simpledialog
from ttkthemes import ThemedTk # Import für modernen Look
import random
import string
import json
import os
import base64
import sys # Für sys.exit()

# --- Verschlüsselungsteil ---
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    # Früher Fehler, falls cryptography fehlt (bevor Tkinter startet)
    print("FEHLER: Die 'cryptography' Bibliothek wird benötigt.")
    print("Bitte installieren: pip install cryptography")
    sys.exit(1) # Beendet das Skript mit Fehlercode

# --- Globale Konstanten ---
PASSWORD_FILE = "passwords.json.enc"
SALT_FILE = "salt.key"

# --- Hilfsfunktionen für Ver-/Entschlüsselung & Schlüsselableitung ---

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Leitet einen Schlüssel vom Master-Passwort und Salt ab."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000, # Beibehaltung der Sicherheit
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Verschlüsselt Daten mit dem gegebenen Schlüssel."""
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_data(token: bytes, key: bytes) -> bytes | None:
    """Entschlüsselt Daten mit dem gegebenen Schlüssel."""
    f = Fernet(key)
    try:
        return f.decrypt(token)
    except InvalidToken:
        # Speziell für falsches Passwort oder korrupte Daten
        return None
    except Exception as e:
        # Andere mögliche Fehler beim Entschlüsseln
        messagebox.showerror("Entschlüsselungsfehler", f"Ein unerwarteter Fehler ist aufgetreten: {e}")
        return None

# --- Startprozess: Master-Passwort holen und Daten laden ---

def get_master_key_and_load_data():
    """
    Kümmert sich um den initialen Passwort-Dialog, Schlüsselableitung und das Laden.
    Wird aufgerufen, bevor das Hauptfenster interaktiv wird.
    Gibt (encryption_key, passwords_data) zurück oder (None, None) bei Abbruch/Fehler.
    """
    salt = None
    # 1. Salt holen oder erstellen
    try:
        if os.path.exists(SALT_FILE):
            with open(SALT_FILE, 'rb') as f:
                salt = f.read()
                if len(salt) != 16: # Überprüfung, ob Salt gültig aussieht
                    messagebox.showerror("Fehler", "Salt-Datei ist korrupt.")
                    return None, None
        else:
            salt = os.urandom(16)
            with open(SALT_FILE, 'wb') as f:
                f.write(salt)
            messagebox.showinfo("Info", "Neuer Salt generiert. Merken Sie sich Ihr Master-Passwort gut!")
    except IOError as e:
        messagebox.showerror("Fehler", f"Konnte Salt-Datei nicht lesen/schreiben: {e}")
        return None, None

    # 2. Master-Passwort abfragen und Schlüssel ableiten/validieren
    encryption_key = None
    passwords_data = {}
    max_attempts = 3 # Maximal 3 Versuche für das Passwort
    attempt = 0

    while attempt < max_attempts:
        password = simpledialog.askstring(
            "Master-Passwort",
            f"Bitte Master-Passwort eingeben (Versuch {attempt + 1}/{max_attempts}):",
            show='*'
        )

        if password is None: # Benutzer hat Abbrechen gedrückt
            messagebox.showwarning("Abbruch", "Kein Master-Passwort eingegeben. Programm wird beendet.")
            return None, None

        if not password:
            messagebox.showwarning("Eingabe fehlt", "Master-Passwort darf nicht leer sein.")
            attempt += 1
            continue # Nächster Versuch

        password_bytes = password.encode('utf-8')
        derived_key = derive_key(password_bytes, salt)
        print("Schlüssel abgeleitet...") # Feedback für den Benutzer

        # 3. Schlüssel validieren durch Laden der Daten (falls Datei existiert)
        if os.path.exists(PASSWORD_FILE) and os.path.getsize(PASSWORD_FILE) > 0:
            print("Validiere Schlüssel durch Entschlüsselung der Daten...")
            try:
                with open(PASSWORD_FILE, 'rb') as f:
                    encrypted_data = f.read()

                decrypted_data_bytes = decrypt_data(encrypted_data, derived_key)

                if decrypted_data_bytes is None:
                    # Entschlüsselung fehlgeschlagen -> Falsches Passwort
                    messagebox.showerror("Fehler", "Falsches Master-Passwort oder beschädigte Passwortdatei.")
                    attempt += 1
                    if attempt == max_attempts:
                         messagebox.showerror("Fehler", "Maximale Anzahl an Versuchen erreicht. Programm wird beendet.")
                         return None, None
                    continue # Nächster Versuch
                else:
                    # Erfolgreich entschlüsselt, Daten parsen
                    try:
                        decrypted_data_str = decrypted_data_bytes.decode('utf-8')
                        passwords_data = json.loads(decrypted_data_str)
                        encryption_key = derived_key # Schlüssel ist korrekt
                        print("Schlüssel validiert und Daten geladen.")
                        break # Schleife verlassen
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        messagebox.showerror("Fehler", "Passwortdatei ist korrupt.")
                        return None, None # Kritischer Fehler

            except IOError as e:
                messagebox.showerror("Fehler", f"Fehler beim Lesen der Passwortdatei: {e}")
                return None, None # Kritischer Fehler
            except Exception as e:
                 messagebox.showerror("Unbekannter Fehler", f"Fehler beim Laden: {e}")
                 return None, None
        else:
            # Keine Passwortdatei vorhanden -> Erster Start mit diesem Schlüssel/Salt
            encryption_key = derived_key
            passwords_data = {}
            print("Keine Passwortdatei gefunden, starte mit leerem Speicher.")
            break # Schleife verlassen

    if encryption_key:
        return encryption_key, passwords_data
    else:
        # Sollte nicht passieren, wenn Logik korrekt ist, aber sicherheitshalber
        return None, None


# --- Hauptanwendungsklasse ---
class PasswordManagerApp:
    def __init__(self, root, key, initial_data):
        self.root = root
        self.encryption_key = key
        self.passwords_data = initial_data

        # --- Tkinter Variablen ---
        self.length_var = tk.StringVar(value="16")
        self.include_lower = tk.BooleanVar(value=True)
        self.include_upper = tk.BooleanVar(value=True)
        self.include_digits = tk.BooleanVar(value=True)
        self.include_symbols = tk.BooleanVar(value=True)
        self.account_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar() # Generiertes PW
        self.loaded_account_var = tk.StringVar()
        self.loaded_username_var = tk.StringVar()
        self.loaded_password_var = tk.StringVar() # Geladenes PW
        self.status_var = tk.StringVar()

        self.setup_gui()
        self.update_password_list() # Liste initial füllen

    def setup_gui(self):
        """Erstellt die grafische Oberfläche."""
        self.root.title("Passwort Generator & Manager (Modern Look)")
        # Optional: Fenstergröße beim Start festlegen
        # self.root.geometry("800x600")

        # --- Layout mit PanedWindow ---
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bd=2) # bd für sichtbaren Rand
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10) # Mehr Padding

        # --- Linker Bereich: Generieren & Speichern ---
        left_frame = ttk.Frame(main_pane, padding="10")
        main_pane.add(left_frame) # weight=1 gibt diesem Bereich Priorität beim Vergrößern

        # -- Generator Optionen --
        options_frame = ttk.LabelFrame(left_frame, text="1. Passwort Optionen", padding="10")
        options_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        ttk.Label(options_frame, text="Länge:").grid(row=0, column=0, padx=5, pady=3, sticky='w')
        ttk.Entry(options_frame, textvariable=self.length_var, width=5).grid(row=0, column=1, padx=5, pady=3, sticky='w')
        ttk.Checkbutton(options_frame, text="Kleinbuchstaben (abc)", variable=self.include_lower).grid(row=1, column=0, columnspan=2, padx=5, pady=3, sticky='w')
        ttk.Checkbutton(options_frame, text="Großbuchstaben (ABC)", variable=self.include_upper).grid(row=2, column=0, columnspan=2, padx=5, pady=3, sticky='w')
        ttk.Checkbutton(options_frame, text="Zahlen (123)", variable=self.include_digits).grid(row=3, column=0, columnspan=2, padx=5, pady=3, sticky='w')
        ttk.Checkbutton(options_frame, text="Sonderzeichen (!?#)", variable=self.include_symbols).grid(row=4, column=0, columnspan=2, padx=5, pady=3, sticky='w')

        # -- Generieren Button --
        generate_button = ttk.Button(left_frame, text="2. Passwort generieren", command=self.generate_password, style='Accent.TButton') # Style für Akzent
        generate_button.grid(row=1, column=0, padx=5, pady=15, sticky="ew")

        # -- Neuer Eintrag Details --
        new_entry_frame = ttk.LabelFrame(left_frame, text="3. Details für neuen Eintrag", padding="10")
        new_entry_frame.grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        ttk.Label(new_entry_frame, text="Generiertes Passwort:").grid(row=0, column=0, padx=5, pady=3, sticky='w')
        password_entry = ttk.Entry(new_entry_frame, textvariable=self.password_var, state="readonly", width=25)
        password_entry.grid(row=0, column=1, padx=5, pady=3, sticky="ew")
        copy_gen_button = ttk.Button(new_entry_frame, text="Kopieren", command=self.copy_generated_password, width=8)
        copy_gen_button.grid(row=0, column=2, padx=5, pady=3)

        ttk.Label(new_entry_frame, text="Account/Webseite:").grid(row=1, column=0, padx=5, pady=3, sticky='w')
        ttk.Entry(new_entry_frame, textvariable=self.account_var, width=25).grid(row=1, column=1, columnspan=2, padx=5, pady=3, sticky="ew")

        ttk.Label(new_entry_frame, text="Benutzername:").grid(row=2, column=0, padx=5, pady=3, sticky='w')
        ttk.Entry(new_entry_frame, textvariable=self.username_var, width=25).grid(row=2, column=1, columnspan=2, padx=5, pady=3, sticky="ew")

        new_entry_frame.columnconfigure(1, weight=1)

        # -- Speichern Button --
        save_button = ttk.Button(left_frame, text="4. Eintrag speichern", command=self.save_entry)
        save_button.grid(row=3, column=0, padx=5, pady=15, sticky="ew")

        left_frame.columnconfigure(0, weight=1)

        # --- Rechter Bereich: Gespeicherte Passwörter ---
        right_frame = ttk.Frame(main_pane, padding="10")
        main_pane.add(right_frame) # weight=2 gibt diesem Bereich mehr Platz beim Vergrößern

        # -- Liste der Passwörter --
        list_frame = ttk.LabelFrame(right_frame, text="Gespeicherte Accounts", padding="10")
        list_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

        self.password_list_tree = ttk.Treeview(list_frame, selectmode="browse", show="tree")
        self.password_list_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.password_list_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.password_list_tree.configure(yscrollcommand=scrollbar.set)
        self.password_list_tree.bind("<<TreeviewSelect>>", self.on_password_select)

        # -- Details des ausgewählten Eintrags --
        details_frame = ttk.LabelFrame(right_frame, text="Ausgewählter Eintrag", padding="10")
        details_frame.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        ttk.Label(details_frame, text="Account:").grid(row=0, column=0, padx=5, pady=3, sticky='w')
        ttk.Entry(details_frame, textvariable=self.loaded_account_var, state="readonly").grid(row=0, column=1, padx=5, pady=3, sticky='ew')

        ttk.Label(details_frame, text="Benutzername:").grid(row=1, column=0, padx=5, pady=3, sticky='w')
        ttk.Entry(details_frame, textvariable=self.loaded_username_var, state="readonly").grid(row=1, column=1, padx=5, pady=3, sticky='ew')

        ttk.Label(details_frame, text="Passwort:").grid(row=2, column=0, padx=5, pady=3, sticky='w')
        loaded_password_entry = ttk.Entry(details_frame, textvariable=self.loaded_password_var, state="readonly")
        loaded_password_entry.grid(row=2, column=1, padx=5, pady=3, sticky='ew')
        copy_load_button = ttk.Button(details_frame, text="Kopieren", command=self.copy_loaded_password, width=8)
        copy_load_button.grid(row=2, column=2, padx=5, pady=3)

        details_frame.columnconfigure(1, weight=1)

        # -- Löschen Button --
        delete_button = ttk.Button(right_frame, text="Ausgewählten Eintrag löschen", command=self.delete_entry, style='Danger.TButton') # Style für Gefahr/Löschen
        delete_button.grid(row=2, column=0, padx=5, pady=15, sticky="ew")

        right_frame.rowconfigure(0, weight=1) # Lässt die Liste wachsen
        right_frame.columnconfigure(0, weight=1)

        # --- Statusleiste ---
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # --- Zusätzliche Styles (optional, abhängig vom Theme) ---
        style = ttk.Style()
        # Definiere ggf. eigene Styles oder passe vorhandene an
        style.configure('Accent.TButton', foreground='white', background='#007bff') # Beispiel für blauen Akzentbutton
        style.configure('Danger.TButton', foreground='white', background='#dc3545') # Beispiel für roten Löschen-Button
        # Hinweis: Farben können je nach Theme überschrieben werden. Besser ist es, Theme-spezifische Styles zu verwenden, falls bekannt.


    # --- Methoden für Funktionalität (angepasst an Klasse) ---

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length <= 0:
                messagebox.showerror("Fehler", "Länge muss positiv sein.", parent=self.root)
                return

            chars = ""
            if self.include_lower.get(): chars += string.ascii_lowercase
            if self.include_upper.get(): chars += string.ascii_uppercase
            if self.include_digits.get(): chars += string.digits
            if self.include_symbols.get(): chars += string.punctuation

            if not chars:
                messagebox.showerror("Fehler", "Bitte mindestens einen Zeichentyp auswählen.", parent=self.root)
                return

            password = ''.join(random.choice(chars) for _ in range(length))
            self.password_var.set(password)
            self.status_var.set("Neues Passwort generiert.")

        except ValueError:
            messagebox.showerror("Fehler", "Ungültige Eingabe für Länge.", parent=self.root)

    def copy_to_clipboard(self, value_to_copy, success_message):
        """Hilfsfunktion zum Kopieren."""
        if value_to_copy:
            self.root.clipboard_clear()
            self.root.clipboard_append(value_to_copy)
            self.status_var.set(success_message)
            # Meldung nach 2 Sekunden löschen
            self.root.after(2000, lambda: self.status_var.set("") if self.status_var.get() == success_message else None)
        else:
            messagebox.showwarning("Nichts zu kopieren", "Es wurde kein Wert zum Kopieren gefunden.", parent=self.root)

    def copy_generated_password(self):
        self.copy_to_clipboard(self.password_var.get(), "Generiertes Passwort kopiert.")

    def copy_loaded_password(self):
        self.copy_to_clipboard(self.loaded_password_var.get(), "Geladenes Passwort kopiert.")

    def save_passwords_to_file(self):
        """Speichert das aktuelle `passwords_data` Dictionary verschlüsselt."""
        if self.encryption_key is None:
            # Sollte nicht passieren, da wir beim Start einen Schlüssel brauchen
            messagebox.showerror("Kritischer Fehler", "Kein Verschlüsselungsschlüssel vorhanden.", parent=self.root)
            return False

        try:
            data_bytes = json.dumps(self.passwords_data, indent=4).encode('utf-8')
            encrypted_data = encrypt_data(data_bytes, self.encryption_key)

            with open(PASSWORD_FILE, 'wb') as f:
                f.write(encrypted_data)
            return True
        except IOError as e:
            messagebox.showerror("Fehler", f"Fehler beim Speichern der Passwortdatei: {e}", parent=self.root)
            return False
        except Exception as e:
            messagebox.showerror("Fehler", f"Unbekannter Fehler beim Speichern: {e}", parent=self.root)
            return False

    def save_entry(self):
        account = self.account_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get() # Das aktuell generierte Passwort

        if not account:
            messagebox.showerror("Fehler", "Accountname darf nicht leer sein.", parent=self.root)
            return
        if not password:
            messagebox.showerror("Fehler", "Bitte zuerst ein Passwort generieren.", parent=self.root)
            return

        entry_key = account

        if entry_key in self.passwords_data:
            if not messagebox.askyesno("Überschreiben?", f"Ein Eintrag für '{account}' existiert bereits.\nWollen Sie ihn überschreiben?", parent=self.root):
                return

        self.passwords_data[entry_key] = {
            "username": username,
            "password": password
        }

        if self.save_passwords_to_file():
            self.status_var.set(f"Eintrag für '{account}' gespeichert.")
            self.update_password_list()
            # Felder optional leeren:
            # self.account_var.set("")
            # self.username_var.set("")
            # self.password_var.set("")
        else:
            # Fehlermeldung kam schon, aber Statusleiste aktualisieren
            self.status_var.set(f"Fehler beim Speichern von '{account}'.")
            # Hier könnte man überlegen, die Änderung in passwords_data rückgängig zu machen

    def update_password_list(self):
        """Aktualisiert die Treeview-Liste mit den Accountnamen."""
        # Alte Einträge löschen
        for item in self.password_list_tree.get_children():
            self.password_list_tree.delete(item)
        # Aktuelle Einträge hinzufügen
        sorted_accounts = sorted(self.passwords_data.keys())
        for account_name in sorted_accounts:
            self.password_list_tree.insert("", tk.END, text=account_name, iid=account_name)
        self.clear_loaded_details() # Auswahl zurücksetzen nach Update

    def on_password_select(self, event=None):
        """Wird aufgerufen, wenn ein Eintrag in der Liste ausgewählt wird."""
        selected_items = self.password_list_tree.selection()
        if not selected_items:
            self.clear_loaded_details()
            return

        selected_item_id = selected_items[0]

        if selected_item_id in self.passwords_data:
            entry_data = self.passwords_data[selected_item_id]
            self.loaded_account_var.set(selected_item_id)
            self.loaded_username_var.set(entry_data.get("username", ""))
            self.loaded_password_var.set(entry_data.get("password", "")) # Passwort aus Speicher
            self.status_var.set(f"Details für '{selected_item_id}' geladen.")
        else:
            self.clear_loaded_details()
            messagebox.showerror("Fehler", "Ausgewählter Eintrag nicht in den Daten gefunden.", parent=self.root)

    def clear_loaded_details(self):
        """Leert die Felder für die geladenen Account-Details."""
        self.loaded_account_var.set("")
        self.loaded_username_var.set("")
        self.loaded_password_var.set("")
        # Ggf. auch Auswahl im Treeview aufheben, falls gewünscht
        # selection = self.password_list_tree.selection()
        # if selection:
        #     self.password_list_tree.selection_remove(selection)

    def delete_entry(self):
        """Löscht den ausgewählten Eintrag."""
        selected_items = self.password_list_tree.selection()
        if not selected_items:
            messagebox.showwarning("Auswahl fehlt", "Bitte zuerst einen Eintrag zum Löschen auswählen.", parent=self.root)
            return

        selected_item_id = selected_items[0]

        if selected_item_id in self.passwords_data:
            if messagebox.askyesno("Löschen bestätigen", f"Wollen Sie den Eintrag für '{selected_item_id}' wirklich löschen?", parent=self.root):
                # Aus dem Speicher löschen
                del self.passwords_data[selected_item_id]

                # Änderungen speichern
                if self.save_passwords_to_file():
                    self.status_var.set(f"Eintrag '{selected_item_id}' gelöscht.")
                    self.update_password_list() # Liste aktualisieren (ruft auch clear_loaded_details auf)
                else:
                    self.status_var.set(f"Fehler beim Speichern nach Löschung von '{selected_item_id}'.")
                    # Hier wäre es gut, die Daten neu zu laden oder das Löschen rückgängig zu machen
                    # z.B. indem man die alten Daten vor dem del sichert und bei Fehler wiederherstellt.
                    messagebox.showerror("Fehler", "Eintrag im Speicher gelöscht, aber Speichern fehlgeschlagen. Daten könnten inkonsistent sein!", parent=self.root)
        else:
             messagebox.showerror("Fehler", "Ausgewählter Eintrag nicht gefunden.", parent=self.root)


# --- Hauptprogrammablauf ---
if __name__ == "__main__":
    # Versuche, Schlüssel zu holen und Daten zu laden *bevor* das Hauptfenster gebaut wird
    print("Starte Passwort-Manager...")
    encryption_key, passwords_data = get_master_key_and_load_data()

    # Wenn kein Schlüssel/Daten geladen wurden (Abbruch oder Fehler), beende.
    if encryption_key is None:
        print("Initialisierung fehlgeschlagen. Programm wird beendet.")
        sys.exit(1)

    print("Initialisierung erfolgreich. Starte GUI...")

    # ThemedTk anstelle von tk.Tk verwenden
    # Mögliche Themes: 'arc', 'plastik', 'adapta', 'clam', 'alt', 'default', 'classic', etc.
    root = ThemedTk(theme="arc")

    # Setze Min/Max-Größe oder Startgröße (optional)
    root.minsize(600, 400)

    # Erstelle die Anwendungsinstanz mit Schlüssel und Daten
    app = PasswordManagerApp(root, encryption_key, passwords_data)

    # Starte den Tkinter Event Loop
    root.mainloop()

    print("Programm beendet.")