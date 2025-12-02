# app.py

import streamlit as st
import time 
from datetime import datetime 
import hashlib
from io import BytesIO
from PIL import Image
import qrcode
from streamlit_cookies_manager import EncryptedCookieManager
import passman_core as core   # your backend logic (crypto + db)

# --- Cookie manager (must have a secret password here, change it!) 
cookies_password = st.secrets["COOKIES_PASSWORD"] 
cookies = EncryptedCookieManager(
    prefix="passman_", 
    password=cookies_password #"change-this-secret-password"
)
if not cookies.ready():
    st.stop()

SESSION_COOKIE = "session_token"
EXPIRY_COOKIE = "session_expiry"
MASTER_COOKIE = "master_password"
TOTP_COOKIE = "totp"

# --- Session helpers ---

def create_session(master_password: str, totp: str):
    """Authenticate and create 24h session."""
    key = core.authenticate_and_get_key(master_password, totp, require_totp=True)
    token = hashlib.sha256(key).hexdigest()
    expiry = int(time.time()) + 24 * 3600
    # Save to cookies
    cookies[SESSION_COOKIE] = token
    cookies[EXPIRY_COOKIE] = str(expiry)
    cookies[MASTER_COOKIE] = master_password
    cookies[TOTP_COOKIE] = totp 
    cookies.save()

def is_logged_in() -> bool:
    token = cookies.get(SESSION_COOKIE)
    expiry = cookies.get(EXPIRY_COOKIE)
    if not token or not expiry:
        return False
    if int(time.time()) > int(expiry):
        logout()
        return False
    return True

def logout():
    for k in [SESSION_COOKIE, EXPIRY_COOKIE, MASTER_COOKIE, TOTP_COOKIE]:
        cookies[k] = "" 
        # cookies.delete(k)
    cookies.save()
    st.success("Logged out ✅")
    # st.rerun()

# --- Pages ---

def page_register():
    st.title("Register (Initialize Vault)")
    if core.db_exists():
        st.warning("Vault already initialized. Please login instead.")
        return
    
    master = st.text_input("Master Password", type="password")
    account_name = st.text_input("Account Name", type="default")
    user_name = st.text_input("User Name", type="default")

    if st.button("Initialize Vault"):
        if len(master) < 8:
            st.error("Password too short (min length 8)")
        else:
            res = core.initialize_vault(master, service_name=account_name, username=user_name)
            uri = res["provisioning_uri"]
            st.success("Vault created!")

            # Show QR code for authenticator
            qr = qrcode.make(uri)
            buf = BytesIO()
            qr.save(buf, format="PNG")
            buf.seek(0)
            st.image(Image.open(buf), caption="Scan this QR in your authenticator app")
            if st.button("Login"):
                st.rerun()
                # page_login()
            # st.code(uri) 

def page_login():
    st.title("Login")
    master = st.text_input("Master Password", type="password")
    totp = st.text_input("TOTP Code")
    if st.button("Login"):
        try:
            create_session(master, totp)
            st.success("Logged in successfully! ✅")
            st.rerun()
        except Exception as e:
            st.error(str(e)) 

def page_dashboard():
    st.sidebar.title("Navigation")
    choice = st.sidebar.radio("Go to", [
        "Add Entry", "Update Entry", "List Entries", "Get Entry",
        "Remove Entry", "Change Master", "Export Backup"
    ])
    st.sidebar.button("Logout", on_click=logout)

    master = cookies.get(MASTER_COOKIE)
    # totp = cookies.get(TOTP_COOKIE) 

    if choice == "Add Entry":
        st.header("Add Entry")
        label = st.text_input("Service")
        username = st.text_input("Username")
        secret = st.text_input("Password/Secret", type="password")
        totp = st.text_input("Authentication Code")
        notes = st.text_area("Notes")

        if st.button("Save Entry"):
            try:
                key = core.authenticate_and_get_key(master, totp, require_totp=True)
                # key = core.authenticate_and_get_key(master, require_totp=False) 
                core.add_entry_with_key(key, label, username, secret, notes)
                st.success("Entry added.")
            except Exception as e:
                st.error(str(e)) 
    elif choice == "Update Entry":
        st.header("Update Username and Password")
        label = st.text_input("Service")
        username = st.text_input("New Username")
        secret = st.text_input("New Password", type="password")
        notes = st.text_area("New Notes") 
        totp = st.text_input("Authentication Code")

        if st.button("Save Entry"):
            try:
                key = core.authenticate_and_get_key(master, totp, require_totp=True)
                # key = core.authenticate_and_get_key(master, require_totp=False) 
                core.update_usrname_pwd_wKey(key, label, username, secret, notes) 
                st.success("Entry Updated.")
            except Exception as e:
                st.error(str(e))
    elif choice == "List Entries":
        st.header("List Entries")
        try:
            key = core.authenticate_and_get_key(master, None, require_totp=False) 
            # key = core.authenticate_and_get_key(master, totp, require_totp=True)
            rows = core.list_labels(key) 
            # st.write(rows) 
            for r in rows:
                # time_obj = datetime.strptime(r[1], "%H:%M:%S")
                # st.write(f"""**{r[0]}** (Created {time_obj.strftime("%I:%M:%S %p")})""")
                st.write(f"**{r[0]}** (Created {r[1]})")
        except Exception as e:
            st.error(str(e))
    elif choice == "Get Entry":
        st.header("Get Entry")
        label = st.text_input("Label to fetch") 
        if st.button("Fetch"):
            try:
                key = core.authenticate_and_get_key(master, None, require_totp=False) 
                # key = core.authenticate_and_get_key(master, totp, require_totp=True)
                entry = core.get_entry_with_key(key, label) 
                st.json(entry)
            except Exception as e:
                st.error(str(e))
    elif choice == "Remove Entry":
        st.header("Remove Entry")
        label = st.text_input("Label to remove") 
        totp = st.text_input("Authentication Code") 

        if st.button("Remove"):
            try:
                key = core.authenticate_and_get_key(master, totp, require_totp=True)
                removed = core.remove_entry_with_key(key, label)
                if removed:
                    st.success("Removed.")
                else:
                    st.warning("Label not found.")
            except Exception as e:
                st.error(str(e))
    elif choice == "Change Master":
        st.header("Change Master Password")
        old_master = st.text_input("Old Master Password", type="password")
        old_totp = st.text_input("Old Auth Code") 
        new_master = st.text_input("New Master Password", type="password")
        if st.button("Change"):
            try:
                core.change_master(old_master, old_totp, new_master)
                st.success("Master password changed.")
            except Exception as e:
                st.error(str(e)) 
    elif choice == "Export Backup":
        st.header("Export Backup")
        backup_pass = st.text_input("Backup Passphrase", type="password")
        if st.button("Export"):
            try:
                key = core.authenticate_and_get_key(master, totp, require_totp=True)
                core.export_backup_file(master, totp, backup_pass, "vault_backup.enc")
                with open("vault_backup.enc", "rb") as f:
                    st.download_button("Download Backup", f, file_name="vault_backup.enc")
            except Exception as e:
                st.error(str(e)) 

# --- Main App ---

def main():
    
    if not core.db_exists():
        st.header("Welcome, to your Password Manager app!")
        page_register()
    elif not is_logged_in():
        page_login()
    else:
        st.header("Welcome, to your Password Manager app!")
        page_dashboard()

if __name__ == "__main__":
    main()
