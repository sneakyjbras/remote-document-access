#!/usr/bin/env python
import tkinter as tk
from tkinter import ttk
import easygui
import sys
import os
import json
import logging
from cStringIO import StringIO
import datetime
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)),"client-side"))
import client

def now():
    return datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

def browse_local_files():
    bool_result = easygui.boolbox("Do you want to send a file or a whole directory?", "Choose file or directory", ["File","Directory"])
    # FILE
    if bool_result:
        filename = easygui.fileopenbox(title="Choose a file")
        if not filename:
            easygui.msgbox("You must choose a file to send.")
            return False
        return filename
    # DIRECTORY
    else:
        dirname = easygui.diropenbox(title="Choose a directory")
        if not dirname:
            easygui.msgbox("You must choose a file to send.")
            return False
        return dirname

class MyHandlerText(logging.StreamHandler):
    def __init__(self, textctrl):
        logging.StreamHandler.__init__(self) # initialize parent
        self.textctrl = textctrl

    def emit(self, record):
        msg = self.format(record)
        self.textctrl.config(state="normal")
        self.textctrl.insert("end", msg + "------\n")
        self.flush()
        self.textctrl.config(state="disabled")

class StdoutCapturer():
    def __init(self):
        self.backup = sys.stdout
    def start(self):
        self.backup = sys.stdout
        sys.stdout = StringIO()     # capture output
    def stop(self):
        out = sys.stdout.getvalue() # release output
        sys.stdout.close()  # close the stream 
        sys.stdout = self.backup # restore original stdout
        return out
    def restart(self):
        out = self.stop()
        self.start()
        return out

# -------------------
# CLIENT FRONTEND API
# -------------------
class CryptoStorageMenu:
    def __init__(self):
        # useful paths
        self.interface_utils_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "interface_utils")
        self.usernames_filepath = self.interface_utils_path + os.sep + "usernames.json"

        # logger for stdout from main
        self.info_logger = logging.getLogger(__name__)
        # current logged in username
        self.current_username = ""
        # window
        self.window = tk.Tk()
        self.window.title("Crypto Storage")
        # favicon
        self.favicon = tk.PhotoImage(file=os.path.join(self.interface_utils_path,"android-chrome-192x192.png"))
        self.window.tk.call("wm", "iconphoto", self.window._w, self.favicon)  
        #self.window.geometry("1600x800+100+100")
        self.window.resizable(0,0)
        #self.window.pack_propagate(0)        # removes dependence of window inside widgets, now window size is free

        self.description_label = tk.Label(self.window, text="Crypto Storage: securely save your files in the cloud", font=("Calibri", 40, "bold"), bg="black", fg="white", borderwidth=2, relief="ridge")
        self.description_label.pack(side="top")

        self.commandlist_box = tk.Listbox(self.window)
        self.account_commandlist_box = tk.Listbox(self.commandlist_box, bg="blue", borderwidth=10)
        self.files_commandlist_box = tk.Listbox(self.commandlist_box, bg="green", borderwidth=10)
        self.info_commandlist_box = tk.Listbox(self.commandlist_box, bg="yellow", borderwidth=10)
        self.exit_commandlist_box = tk.Listbox(self.commandlist_box, bg="red", borderwidth=10)
        self.commandlist_box.pack(side="left")
        self.account_commandlist_box.pack()
        self.files_commandlist_box.pack()
        self.info_commandlist_box.pack()
        self.exit_commandlist_box.pack()
        #self.mascot_img = tkinter.PhotoImage(file=os.path.join(self.interface_utils_path,"chibi-superman-smaller.png"))
        #self.mascot_label = tkinter.Label(self.window, image=self.mascot_img)
        #self.mascot_label.pack(side="top")

        self.log_box_label = tk.Label(self.window, text="Client log box", font=("Calibri", 20, "bold"), bg="yellow", fg="black", borderwidth=2, relief="ridge")
        self.log_box_label.pack(side="top", fill="x")
        self.log_box = tk.Text(self.window, state="disabled")
        self.log_box.pack(side="top", fill="x")

        # ACCOUNT COMMANDS
        self.registerButton = tk.Button(self.account_commandlist_box, text="Register", justify="center", font=("Calibri", 12), height=2, width=40, bg="#33FFFF", fg="black", borderwidth=2, relief="groove", command=self.register)
        self.loginButton = tk.Button(self.account_commandlist_box, text="Login", justify="center", font=("Calibri", 12), height=2, width=40, bg="#33FFFF", fg="black", borderwidth=2, relief="groove", command=self.choose_user)
        self.forgetButton = tk.Button(self.account_commandlist_box, text="Forget user", justify="center", font=("Calibri", 12), height=2, width=40, bg="#33FFFF", fg="black", borderwidth=2, relief="groove", command=self.forget_user)
        self.registerButton.pack()
        self.loginButton.pack()
        self.forgetButton.pack()

        # FILES COMMANDS
        self.listFilesButton = tk.Button(self.files_commandlist_box, text="List private files (in the server)", justify="center", font=("Calibri", 12), height=2, width=40, bg="#66FF66", fg="black", borderwidth=2, relief="groove", command=self.list_individual)
        self.sendPrivateButton = tk.Button(self.files_commandlist_box, text="Send private files", justify="center", font=("Calibri", 12), height=2, width=40, bg="#66FF66", fg="black", borderwidth=2, relief="groove", command=self.send_individual)
        self.fetchPrivateButton = tk.Button(self.files_commandlist_box, text="Fetch private files", justify="center", font=("Calibri", 12), height=2, width=40, bg="#66FF66", fg="black", borderwidth=2, relief="groove", command=self.fetch_individual)
        self.deletePrivateButton = tk.Button(self.files_commandlist_box, text="Delete private files", justify="center", font=("Calibri", 12), height=2, width=40, bg="#66FF66", fg="black", borderwidth=2, relief="groove", command=self.delete_individual)
        self.listFilesButton.pack()
        self.sendPrivateButton.pack()
        self.fetchPrivateButton.pack()
        self.deletePrivateButton.pack()

        # INFO COMMANDS
        self.logBoxButton = tk.Button(self.info_commandlist_box, text="Clear log box", justify="center", font=("Calibri", 12), height=2, width=40, bg="yellow", fg="black", borderwidth=2, relief="groove", command=self.clear_log_box)
        self.logBoxButton.pack()

        # EXIT COMMAND
        self.closeAppButton = tk.Button(self.exit_commandlist_box, text="Close app", justify="center", font=("Calibri", 12), height=2, width=40, bg="red", fg="black", borderwidth=2, relief="groove", command=self.window.destroy)
        self.closeAppButton.pack()

        # INFO LOGGER
        self.guiHandler = MyHandlerText(self.log_box)
        self.info_logger.addHandler(self.guiHandler)
        self.info_logger.setLevel(logging.INFO)
        self.window.mainloop()

    # AUX FUNCTIONS
    def get_usernames_info(self):
        # create usernames file if it doesn't exist yet
        if not os.path.exists(self.usernames_filepath):
            open(self.usernames_filepath, "a").close()
        try:
            usernames_json_f = open(self.usernames_filepath, "r")
            usernames_list = json.loads(usernames_json_f.read())
        except ValueError:
            usernames_list = list()
        usernames_json_f.close()
        return usernames_list

    def relog(self):
        out = stdout_capturer.restart()
        self.info_logger.info(out)
        return out

    def verify_chosen_username(self):
        if not self.current_username:
            easygui.msgbox("You must choose your user first! Please login.")
            return False
        return True

    def update_usernames_list(self, username):
        usernames_list = self.get_usernames_info()
        if username not in usernames_list:
            usernames_list.append(username)
            usernames_json_f = open(self.usernames_filepath, "w")
            json.dump(usernames_list, usernames_json_f)
            usernames_json_f.close()
        return

    # INTERFACE FUNCTIONS
    def register(self):
    	username = easygui.enterbox("Register user:")
        if not username:
            return
        if cryptoStorageBackendAPI.register(username):
            self.update_usernames_list(username)
        self.relog()
        
    def choose_user(self):
        usernames_list = self.get_usernames_info()
        username = easygui.choicebox("What account do you want to use?", "Choose user to login with", usernames_list + ["Other"])
        if not username:
            return
        elif username=="Other":
            username = easygui.enterbox("Username:")
            if not username:
                return
        if cryptoStorageBackendAPI.authenticate(username, fast_auth=True):
            self.update_usernames_list(username)
            self.current_username = username
        self.relog()

    def forget_user(self):
        usernames_list = self.get_usernames_info()
        username = easygui.choicebox("What account do you wish to forget?", "Forget user", usernames_list)
        if not username:
            return
        usernames_list.remove(username)
        f = open(self.usernames_filepath, "w")
        json.dump(usernames_list, f)
        f.close()
        easygui.msgbox("User \"" + username + "\" forgotten.")

    def send_individual(self):
        if not self.verify_chosen_username():
            return
        cryptoStorageBackendAPI.send_individual(self.current_username)
        self.relog()

    def fetch_individual(self):
        if not self.verify_chosen_username():
            return
        cryptoStorageBackendAPI.fetch_individual(self.current_username)
        self.relog()

    def show_info_box(self):
        return

    def clear_log_box(self):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")
        return

    def list_individual(self):
        if not self.verify_chosen_username():
            return
        cryptoStorageBackendAPI.list_individual(self.current_username)
        self.relog()
        return

    def delete_individual(self):
        if not self.verify_chosen_username():
            return
        cryptoStorageBackendAPI.delete_individual(self.current_username)
        self.relog()
        return

# ------------------
# CLIENT BACKEND API
# ------------------
class CryptoStorageBackendAPI:
    def __init__(self):
        self.args_dict = vars(client.client_global.args)
        self.client_error_sig = "[!]"

    def reset_client_args_dict(self, target_dict):
        for var_name in target_dict:
            var_value = target_dict[var_name]
            if isinstance(var_value, bool):
                target_dict[var_name] = False
            elif isinstance(var_value, str):
                target_dict[var_name] = ""
        target_dict["production"] = True
        return target_dict

    def help(self):
        # TODO: help in log box
        pass

    def register(self, name):
        self.args_dict = self.reset_client_args_dict(self.args_dict)
        self.args_dict["register"] = name
        client.run()
        if client.client_global.interface_error_msg[0:3]==self.client_error_sig:
            return False
        return True

    # authentication is present with every other action
    def authenticate(self, name, fast_auth=False):
        self.args_dict = self.reset_client_args_dict(self.args_dict)
        self.args_dict["login"] = name
        if fast_auth:
            self.args_dict["explicitauth"] = True
            client.run()
            if client.client_global.interface_error_msg[0:3]==self.client_error_sig:
                return False
            self.args_dict["explicitauth"] = False
        return True

    def list_individual(self, name):
        if not self.authenticate(name):
            return
        self.args_dict["listindividualfiles"] = True
        client.run()

    def list_shared_files(self, name):
        if not self.authenticate(name):
            return
        self.args_dict["listsharedfiles"] = True
        client.run()

    def send_individual(self, name):
        chosen_filename = browse_local_files()
        if not chosen_filename:
            return
        if not self.authenticate(name):
            return
        self.args_dict["sendindividualfiles"] = chosen_filename
        client.run()

    def fetch_individual(self, name):
        # TODO: browse_remote_files
        chosen_filename = browse_local_files()
        if not chosen_filename:
            return
        if not self.authenticate(name):
            return
        self.args_dict["fetchindividualfiles"] = chosen_filename
        client.run()
        # TODO: open fetched location in file explorer

    def delete_individual(self, name):
        # TODO: browse_remote_files
        chosen_filename = browse_local_files()
        if not chosen_filename:
            return
        if not self.authenticate(name):
            return
        self.args_dict["deleteindividualfiles"] = chosen_filename
        client.run()

    def list_users(self, name):
        if not self.authenticate(name):
            return
        self.args_dict["listallusers"] = True
        client.run()

    def list_backups(self, name):
        if not self.authenticate(name):
            return
        self.args_dict["listmybackups"] = True
        client.run()

if __name__ == "__main__": # Only runs program if this specfic file is opened.
    cryptoStorageBackendAPI = CryptoStorageBackendAPI()
    stdout_capturer = StdoutCapturer()
    stdout_capturer.start()
    CryptoStorageMenu()