# CLIENT
try:
    import socket
    import ssl
    import argparse
    import os
    import sys
    import errno
    import time
    import datetime
    import json
    import subprocess
    import hashlib
    import argcomplete
    # our custom modules
    this_script_dirpath = os.path.dirname(os.path.realpath(__file__))
    sys.path.insert(0, this_script_dirpath + os.sep + "utils" + os.sep + "aux-py-modules")
    import AESCipher
except ImportError:
    raise ImportError("You need to do 'pip install -r requirements.txt' to be able to use this program.")

# PRELIMINARY NOTE: read the README.txt for informations about how to run this file
# READING:
# [!]: error information
# [+]: normal information

# HMAC w/ sha256 (not used anymore now)
def hmac_sha256(content, secret_key):
    # more info: https://en.wikipedia.org/wiki/HMAC
    # slides: HMAC(m,k) = hash(k^opad + hash(k^ipad+m))
    outter_padding_str = "".join([chr(x^0x5C) for x in range(256)])
    inner_padding_str = "".join([chr(x^0x36) for x in range(256)])
    outer_key_padding = hashlib.sha256()
    inner_key_padding = hashlib.sha256()
    # padding key with 0's
    secret_key = secret_key + '\x00' * (inner_key_padding.block_size - len(secret_key))

    outer_key_padding.update(secret_key.translate(outter_padding_str))
    inner_key_padding.update(secret_key.translate(inner_padding_str))
    inner_key_padding.update(content)
    outer_key_padding.update(inner_key_padding.digest())

    hmac = outer_key_padding.hexdigest()
    return hmac

def encrypt_key(aeskey_bytecode, pubkey_path):
    script_path = this_script_dirpath + os.sep + "utils" + os.sep + "CLIENT_ENCRYPT_SYMKEY.sh"
    proc = subprocess.Popen([script_path,aeskey_bytecode, pubkey_path], stdout=subprocess.PIPE)
    encrypted_aeskey_bytecode = proc.stdout.read().encode("hex")
    return encrypted_aeskey_bytecode

def decrypt_key(encrypted_aeskey_bytecode, privkey_path):
    script_path = this_script_dirpath + os.sep + "utils" + os.sep + "CLIENT_DECRYPT_SYMKEY.sh"
    encrypted_aeskey = encrypted_aeskey_bytecode.decode("hex")
    tmp_encryptedkeyfile = "symkey.bin.encrypted"
    f = open(tmp_encryptedkeyfile, "w")
    f.write(encrypted_aeskey)
    f.close()
    proc = subprocess.Popen([script_path,tmp_encryptedkeyfile, privkey_path], stdout=subprocess.PIPE)
    decrypted_aeskey_bytecode = proc.stdout.read()[:-1]
    return decrypted_aeskey_bytecode

def encrypt_file(filepath, aeskey_bytecode, iv_bytecode, client_name):
    aeskey = bytearray.fromhex(aeskey_bytecode)
    aesiv = bytearray.fromhex(iv_bytecode)
    aeskeybuffer = buffer(aeskey)
    aesivbuffer = buffer(aesiv)
    aesCipher = AESCipher.AESCipher(aeskeybuffer)
    f = open(filepath)
    filecontent = f.read()
    f.close()
    filecontent_clientname = filecontent + "\n" + client_name
    ciphered_text = aesCipher.encrypt(filecontent_clientname, aesivbuffer)
    return ciphered_text

def sign_file(ciphertext_filepath, privkey_path):
    cmd = this_script_dirpath + os.sep + "utils" + os.sep + "CLIENT_SIGN_DOCUMENT.sh " + ciphertext_filepath + " " + privkey_path
    subprocess.check_call(cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
    return ciphertext_filepath + ".sig"

def decrypt_filecontent(encrypted_filecontent, aeskey_bytecode):
    aeskey = bytearray.fromhex(aeskey_bytecode)
    aeskeybuffer = buffer(aeskey)
    file_bcbuffer = buffer(encrypted_filecontent)
    aesCipher = AESCipher.AESCipher(aeskeybuffer)
    deciphered_text = aesCipher.decrypt(file_bcbuffer)
    return deciphered_text

def verify_digital_signature(pubkey_path,sig_filepath,cryptogram_filepath):
    cmd = "openssl dgst -sha256 -verify " + pubkey_path + " -signature " + sig_filepath + " " + cryptogram_filepath
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    sig_verification = proc.stdout.read()
    return sig_verification=="Verified OK\n"

def reconstruct_client_files(file_structure, clientside_dirname, client_name, sharedfiles_flag=False):
    privkey_path = client_global.mycert_dir + os.sep + client_name + ".key"
    for clientside_directory in file_structure:
        files = file_structure[clientside_directory]
        if sandbox_escaped(clientside_directory, clientside_dirname):
            exit()
        mkdir_p(clientside_directory)
        for filename in files:
            if filename.endswith(".key.encrypted") or filename.endswith(".key.encrypted." + client_name) or filename.endswith(".sig"):
                pass
            else:
                filename_noext = filename.rsplit(".encrypted", 1)[0]
                clientside_filepath = clientside_directory + os.sep + filename_noext
                if sandbox_escaped(clientside_filepath, clientside_dirname):
                    exit()
                encrypted_filecontent_bytecode = files[filename][0]
                key_entry = filename_noext + ".key.encrypted" if not sharedfiles_flag else filename_noext + ".key.encrypted." + client_name
                sig_entry = filename_noext + ".sig"
                encrypted_aeskey_bytecode = files[key_entry][0]
                signature_bytecode = files[sig_entry][0]

                aeskey_bytecode = decrypt_key(encrypted_aeskey_bytecode, privkey_path)
                encrypted_filecontent = encrypted_filecontent_bytecode.decode("hex")
                decrypted_filecontent = decrypt_filecontent(encrypted_filecontent, aeskey_bytecode)
                decrypted_filecontent_split = decrypted_filecontent.rsplit("\n", 1)
                try:
                    relevant_decipheredtext = decrypted_filecontent_split[0]
                    lastmodifier_clientname = decrypted_filecontent_split[1]
                except IndexError:
                    print "[!][" + now() + "] No last line. This must mean the file you're trying to fetch has been illicitly modified. Aborting..."
                    exit()

                # already exists in the directory in the case of individual_files
                lastmodifier_pubkey_path = client_global.mycert_dir + os.sep + lastmodifier_clientname + ".pubkey" if not sharedfiles_flag \
                                            else client_global.shareuser_certs_dir + os.sep + lastmodifier_clientname + ".pubkey"
                signature = signature_bytecode.decode("hex")
                tmp_sig_filepath = this_script_dirpath + os.sep + "tmp_" + sig_entry
                f = open(tmp_sig_filepath, "w")
                f.write(signature)
                f.close()
                tmp_cryptogram_filepath = this_script_dirpath + os.sep + "tmp_" + filename
                f = open(tmp_cryptogram_filepath, "w")
                f.write(encrypted_filecontent)
                f.close()
                sig_verified = verify_digital_signature(lastmodifier_pubkey_path, tmp_sig_filepath, tmp_cryptogram_filepath)
                os.remove(tmp_sig_filepath)
                os.remove(tmp_cryptogram_filepath)
                if not sig_verified:
                    print "[!][" + now() + "] Ciphered-file signature not verified: file \"%s\" wasn't signed by %s, which was alledgedly the last signer of the document" \
                        %(tmp_cryptogram_filepath, lastmodifier_clientname)
                    exit()
                f = open(clientside_filepath, "w")
                f.write(relevant_decipheredtext)
                f.close()
    return True

def read_in_chunks(conn):
    data_len = int(conn.read())
    chunk_len = min(data_len, 16384)   # limit size before waiting
    data_repr = ""
    i=chunk_len
    while i<=data_len:
        data_repr += conn.recv(chunk_len)
        i += chunk_len
    if data_len%chunk_len!=0:
        data_repr += conn.recv(data_len%16384)
    data = json.loads(data_repr)
    return conn, data

def locally_generate_symkey():
    script_path = this_script_dirpath + os.sep + "utils" + os.sep + "CLIENT_GEN_SYMKEY.sh"
    proc = subprocess.Popen([script_path], stdout=subprocess.PIPE)
    subpro_output = proc.stdout.read()
    split_output = subpro_output.splitlines()
    aeskey_bytecode = split_output[0].split('=')[1]
    iv_bytecode = split_output[1].split('=')[1]
    return aeskey_bytecode, iv_bytecode

def path_traversal_verified(suspect_filepath, highestlevel_dirname):
    if os.path.commonprefix((os.path.realpath(suspect_filepath),os.path.abspath(highestlevel_dirname))) != os.path.abspath(highestlevel_dirname):
        return False
    return True

def sandbox_escaped(currentside_filepath, currentside_dirname):
    if not path_traversal_verified(currentside_filepath, currentside_dirname):
        print "[!][" + now() + "] An error occurred, the server sent us an invalid file structure. Aborting..."
        return True
    return False

def get_digital_signature(encrypted_filecontent, privkey_path):
    tmp_ciphertext_filepath = this_script_dirpath + os.sep + "tmp_ciphered"
    f = open(tmp_ciphertext_filepath, "w")
    f.write(encrypted_filecontent)
    f.close()
    sig_filepath = sign_file(tmp_ciphertext_filepath, privkey_path)
    f = open(sig_filepath)
    signature = f.read()
    f.close()
    os.remove(tmp_ciphertext_filepath)
    os.remove(sig_filepath)
    return signature

# slides: A ---> B: {{"Alice", plaintext}B,#plaintext}a
def file_prepare(currentside_filepath, filebasename, client_name, file_structure):
    privkey_path = client_global.mycert_dir + os.sep + client_name + ".key"
    pubkey_path = client_global.mycert_dir + os.sep + client_name + ".pubkey"
    aeskey_bytecode, iv_bytecode = locally_generate_symkey()
    encrypted_filecontent_bytecode = encrypt_file(currentside_filepath, aeskey_bytecode, iv_bytecode, client_name)
    encrypted_aeskey_bytecode = encrypt_key(aeskey_bytecode, pubkey_path)
    encrypted_filecontent = encrypted_filecontent_bytecode.decode("hex")
    signature = get_digital_signature(encrypted_filecontent, privkey_path)
    signature_bytecode = signature.encode("hex")
    file_structure[os.path.dirname(currentside_filepath)][filebasename] = \
        [encrypted_filecontent_bytecode, encrypted_aeskey_bytecode, signature_bytecode, os.path.getmtime(currentside_filepath)]
    return file_structure

# slides: A ---> B: {{"Alice", plaintext}B,#plaintext}a
def sharedfile_prepare(currentside_filepath, filebasename, user_certs, client_name, sharedfile_structure):
    privkey_path = client_global.mycert_dir + os.sep + client_name + ".key"
    aeskey_bytecode, iv_bytecode = locally_generate_symkey()
    encrypted_filecontent_bytecode = encrypt_file(currentside_filepath, aeskey_bytecode, iv_bytecode, client_name)
    encrypted_filecontent = encrypted_filecontent_bytecode.decode("hex")
    signature = get_digital_signature(encrypted_filecontent, privkey_path)
    signature_bytecode = signature.encode("hex")
    sharedfile_structure[os.path.dirname(currentside_filepath)][filebasename] = [encrypted_filecontent_bytecode, signature_bytecode, os.path.getmtime(currentside_filepath)]
    for user in user_certs:
        cert = user_certs[user]
        shareuser_cert_path = client_global.shareuser_certs_dir + os.sep + user + ".crt"
        f = open(shareuser_cert_path, "w")
        f.write(cert)
        f.close()
        verify_received_certificate(shareuser_cert_path)
        # getting public keys from received certificates
        shareuser_pubkey_path = client_global.shareuser_certs_dir + os.sep + user + ".pubkey"
        cmd = "openssl x509 -inform pem -in " + shareuser_cert_path + " -pubkey -out " + shareuser_pubkey_path
        subprocess.check_call(cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
        encrypted_aeskey_bytecode = encrypt_key(aeskey_bytecode, shareuser_pubkey_path)
        sharedfile_structure[os.path.dirname(currentside_filepath)][filebasename].append([user, encrypted_aeskey_bytecode])
    return sharedfile_structure

def filestructure_prepare(currentside_dirname, pubkey_path, client_name, file_structure, user_certs=False, sharedfiles_flag=False):
    for filebasename in os.listdir(currentside_dirname):
        currentside_filepath = currentside_dirname + os.sep + filebasename
        try:
            remoteside_filepath = currentside_filepath.split(currentside_dirname, 1)[1].lstrip(os.sep)
        except IndexError:
            print "[!][" + now() + "] You didn't specify a path within the \"myprivatefiles\" directory, aborting..."
            exit()
        if os.path.isdir(currentside_filepath):
            file_structure[currentside_filepath] = dict()
            file_structure = filestructure_prepare(currentside_filepath, pubkey_path, client_name, file_structure, user_certs, sharedfiles_flag)
    for filebasename in os.listdir(currentside_dirname):
        currentside_filepath = currentside_dirname + os.sep + filebasename
        remoteside_filepath = currentside_filepath.split(currentside_dirname, 1)[1].lstrip(os.sep)
        if not os.path.isdir(currentside_filepath) and not sharedfiles_flag:
            file_structure = file_prepare(currentside_filepath, filebasename, client_name, file_structure)
        elif not os.path.isdir(currentside_filepath) and sharedfiles_flag:
            file_structure = sharedfile_prepare(currentside_filepath, filebasename, user_certs, client_name, file_structure)
    return file_structure

def sanitize_clientname(client_name):
    removed_str_list = [" ", "\"", "'", "\\", "/", ".", "-", ";", "\n", "=", ",", "*", "@", "%", "$", "!"]
    for character in removed_str_list:
        client_name = client_name.replace(character,"")
    return client_name

def modify_client_csr_config(client_csr_config, client_name):
    client_csr_config = client_csr_config.replace("O = SIRS Client", "O = " + client_name)
    client_csr_config = client_csr_config.replace("CN = *.sirs-client.org", "CN = *." + client_name + ".org")
    client_csr_config = client_csr_config.replace("DNS.1 = *.sirs-client.org", "DNS.1 = *." + client_name + ".org")
    client_csr_config = client_csr_config.replace("DNS.2 = *.sirs-client.net", "DNS.2 = *." + client_name + ".net")
    client_csr_config = client_csr_config.replace("DNS.3 = *.sirs-client.in", "DNS.3 = *." + client_name + ".in")
    client_csr_config = client_csr_config.replace("DNS.4 = sirs-client.org", "DNS.4 = " + client_name + ".org")
    client_csr_config = client_csr_config.replace("DNS.5 = sirs-client.net", "DNS.5 = " + client_name + ".net")
    client_csr_config = client_csr_config.replace("DNS.6 = sirs-client.in", "DNS.6 = " + client_name + ".in")
    return client_csr_config

def now():
    return datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def locally_generate_csr(client_name):
    if not client_global.args.production: print "[+][" + now() + "] Generating my certificate signing request..."
    client_csr_config_filename = client_global.utils_dir + os.sep + "conf_client" + os.sep + "client_crt_config.conf"
    # MODIFY CONFIG FILE BASED ON CLIENT NAME
    f = open(client_csr_config_filename, "r")
    original_client_csr_config = f.read()
    f.close()
    client_csr_config = modify_client_csr_config(original_client_csr_config, client_name)
    f = open(client_csr_config_filename, "w")
    f.write(client_csr_config)
    f.close()

    # GENERATE CSR BASED ON CONFIG FILE
    cmd = client_global.utils_dir + os.sep + "CLIENT_CERTS_KEYPAIRS.sh " + client_global.utils_dir
    subprocess.check_call(cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
    os.rename(client_global.mycert_dir + os.sep + "sirs-client.key", client_global.mycert_dir + os.sep + client_name + ".key")
    os.rename(client_global.mycert_dir + os.sep + "sirs-client.pubkey", client_global.mycert_dir + os.sep + client_name + ".pubkey")
    mycert_path = client_global.mycert_dir + os.sep + "sirs-client.csr"
    f = open(mycert_path, "r")
    cert_sign_request = f.read()
    f.close()
    # RESTORE CLIENT CONFIG FILE
    f = open(client_csr_config_filename, "w")
    f.write(original_client_csr_config)
    f.close()
    return cert_sign_request

def list_my_files(mutual_conn, client_name, tag="ALL"):
    mutual_conn.send("LIST-FILES")
    if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'LIST-FILES'"
    # output is of form "file [last-time synchronized]"
    mutual_conn, individualfile_structure = read_in_chunks(mutual_conn)
    mutual_conn, sharedfile_structure_list = read_in_chunks(mutual_conn)
    if tag=="ALL" or tag=="Individual-Only":
        mutual_conn = list_individual_files(mutual_conn, individualfile_structure)
    if tag=="ALL" or tag=="Shared-Only":
        mutual_conn = list_shared_files(mutual_conn, sharedfile_structure_list, client_name)
    return mutual_conn

def list_individual_files(mutual_conn, individualfile_structure):
    output_header = "[+][" + now() + "] Private files saved server-side:"
    files_list = ""
    for clientside_directory in individualfile_structure:
        for filebasename in individualfile_structure[clientside_directory]:
            if filebasename.endswith(".key.encrypted"):
                continue
            elif filebasename.endswith(".sig"):
                continue
            elif filebasename.endswith(".encrypted"):
                files_list += "\n- " + clientside_directory + os.sep + filebasename.rsplit(".",1)[0] + " [" + individualfile_structure[clientside_directory][filebasename] + "]"
            else:
                print "[!][" + now() + "] Something went wrong. Aborting..."
                exit()
    if not files_list:
        print "[-][" + now() + "] You have no private files saved in the server."
    else:
        print output_header + files_list
    return mutual_conn

def list_shared_files(mutual_conn, sharedfile_structure_list, client_name):
    files_list = "Shared files saved server-side:"
    for sharedfile_structure in sharedfile_structure_list:
        for clientside_directory in sharedfile_structure:
            for filebasename in sharedfile_structure[clientside_directory]:
                if filebasename.endswith(".key.encrypted." + client_name):
                    continue
                elif filebasename.endswith(".encrypted"):
                    files_list += "\n- " + clientside_directory + os.sep + filebasename.rsplit(".",1)[0] + " [" + sharedfile_structure[clientside_directory][filebasename] + "]"
                else:
                    print "[!][" + now() + "] Something went wrong. Aborting..."
                    exit()
    if files_list=="Shared files saved server-side:":
        print "You have no shared files saved in the server."
    else:
        print files_list
    return mutual_conn

def verify_pre_conditions():
    client_name = ""
    args_list = [client_global.args.register!="", client_global.args.login!="",\
                client_global.args.listindividualfiles, client_global.args.sendindividualfiles!="", client_global.args.fetchindividualfiles!="", client_global.args.deleteindividualfiles!="",\
                client_global.args.listallusers, client_global.args.share!="", client_global.args.fetchshared!="", client_global.args.sendshared!="",\
                client_global.args.listmybackups, client_global.args.revert, client_global.args.revertshared]

    if True not in args_list:
        print "[!][" + now() + "] You need to choose an option."
        client_global.oparser.print_help()
        exit()
    
    if client_global.args.register and True in args_list[1:]:
        print "[!][" + now() + "] You need to choose only ONE option alongside the 'register' option."
        exit()

    if client_global.args.sendindividualfiles or client_global.args.fetchindividualfiles or client_global.args.share or client_global.args.fetchshared or client_global.args.sendshared:
        if args_list[2:].count(True)!=1:
            print "[!][" + now() + "] You can only send individual files, fetch individual files, list your files," + \
                        " list all users, share, fetch shared files or send shared files, one action at a time." 
            exit()

    if not client_global.args.login and True in args_list[2:]:
        print "[!][" + now() + "] You can only perform the specified action if you authenticate yourself first. Please specify option 'login'." 
        exit()

    #if client_global.args.login and True not in (args_list[:1]+args_list[2:]):
    #    print "[!][" + now() + "] Please have in mind that when you authenticate yourself to the server you should be performing an action." + \
    #    " Your login state is not persistent, i.e., you have to authenticate yourself (login) everytime you want to perform an action that requires it." 
    #    exit()

    if client_global.args.register:
        client_name = client_global.args.register
    elif client_global.args.login:
        client_name = client_global.args.login

    if not client_name:
    	print "[!][" + now() + "] Error, you didn't specify your client name with the register/login option."
        exit()

    return client_name

def create_file_structure(clientside_path, client_name):
    pubkey_path = client_global.mycert_dir + os.sep + client_name + ".pubkey"
    filebasename = os.path.basename(clientside_path)
    file_structure = dict()
    if os.path.isfile(clientside_path):
        clientside_directory = os.path.dirname(clientside_path)
        file_structure[clientside_directory] = dict()     # current dir
        file_structure = file_prepare(clientside_path, filebasename, client_name, file_structure)
    elif os.path.isdir(clientside_path):
        file_structure[clientside_path] = dict()     # current dir
        file_structure = filestructure_prepare(clientside_path, pubkey_path, client_name, file_structure)
    else:
        print "[!][" + now() + "] You are trying to send a non-existent file or directory. Aborting..."
        exit()
    return file_structure

def send_in_chunks(conn, data):
    data_repr = json.dumps(data)
    data_repr_len = len(data_repr)
    conn.send(str(data_repr_len))
    conn.send(data_repr)
    return conn

def verify_received_certificate(cert_path):
    cmd = "openssl verify -verbose -CAfile " + client_global.clientside_certificates_trustanchor_path + " " + cert_path
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    cert_verification = proc.stdout.read()
    if cert_verification==cert_path + ": OK\n":
        return True
    else:
        print "[!][" + now() + "] Received certificate (%s) isn't signed by server, something has gone wrong! Deleting certificate and aborting..." %(cert_path)
        os.remove(cert_path)
        exit()

def list_my_backups(mutual_conn, client_name, tag="ALL"):
    if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'LIST-MY-BACKUPS'"
    mutual_conn.send("LIST-MY-BACKUPS")
    mutual_conn, individual_backups_list = read_in_chunks(mutual_conn)
    mutual_conn, shared_backups_list = read_in_chunks(mutual_conn)
    if tag=="ALL" or tag=="Individual-Only":
        print "You have the following individual backup directories: "
        for i, individual_backup_directory in enumerate(individual_backups_list):
            print "(" + str(i + 1) + ")" + " : " + individual_backup_directory
    if tag=="ALL" or tag=="Shared-Only":
        print "You have the following shared backup directories: "
        for i, shared_backup_directory in enumerate(shared_backups_list):
            print "(" + str(i + 1) + ")" + " : " + shared_backup_directory
    return mutual_conn, individual_backups_list, shared_backups_list

def verify_individual_location(input_location):
    if client_global.myprivatefiles_dir not in os.path.commonprefix((os.path.realpath(input_location),os.path.abspath(client_global.myprivatefiles_dir))):
        client_global.interface_error_msg = "[!][" + now() + "] Please provide me with a file or directory inside the \"myprivatefiles\" directory. Aborting..."
        print client_global.interface_error_msg
        return False
    return True

def client():
    client_name = verify_pre_conditions()
    simple_banner = "###################### SIRS-CLIENT ######################"
    if not client_global.args.production: print simple_banner

    HOST = "127.0.0.1"        # testing in local host (change if needed)
    PORT = 1337               # server port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # TLS VERSION USED: TLSv1.2
    # the purpose of this ssl wrapper is to authenticate the server to the client
    initial_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # tell the SSLContext that we want our peer's (server) certificate and its inherent CA validation
    initial_ssl_context.verify_mode = ssl.CERT_REQUIRED
    # we have a fake domain name in the server certificate, which we will verify
    initial_ssl_context.check_hostname = True

    # server auth
    # load our trusted certificate authority certificate to check if it is the same CA that
    # validated the server certificate we are going to receive from the server in a step ahead
    # (this goes with our assumption that client has the CA certificate previously installed)
    initial_ssl_context.load_verify_locations(client_global.clientside_trustanchor_path)

    # conn object requires a certificate signed by the specific CA because of the context object
    conn = initial_ssl_context.wrap_socket(sock, server_side=False, server_hostname = "*.sirs-server.org", do_handshake_on_connect=True)

    # CONNECTION
    # if the connection is successful, then the presented certificate was signed by the CA certificate we provided above
    conn.connect((HOST, PORT))
    if not client_global.args.production: print "[+][" + now() + "] Started a %s connection with the server." %(conn.version())

    # if this reached this point, the server's certificate is trusted and we have a basic TLS connection between our
    # client and our server. The client now knows he's talking to the right server.
    if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'HELLO' (server is trusted)"
    conn.send("HELLO")
    if conn.read() != client_global.OK_MSG:
        print "[!][" + now() + "] Server didn't respond to the hello message."
        return

    client_name = sanitize_clientname(client_name)
    if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'NAME: %s'" %(client_name)
    conn.send("NAME: " + client_name)
    registered_status = conn.read()

    if registered_status == "REGISTERED":
        registered_status = True
    elif registered_status == "NOT-REGISTERED":
        registered_status = False
    else:
        print "[!][" + now() + "] Something went wrong, aborting..."
        exit()

    if client_global.args.register and registered_status:
        client_global.interface_error_msg = "[!][" + now() + "] User \"%s\" is already registered." %(client_name)
        print client_global.interface_error_msg
        return
    elif client_global.args.login and not registered_status:
        client_global.interface_error_msg = "[!][" + now() + "] User \"%s\" is not registered yet." %(client_name)
        print client_global.interface_error_msg
        return
    # REGISTER CODE BLOCK
    elif client_global.args.register and not registered_status:
        # generating csr and sending to server
        cert_sign_request = locally_generate_csr(client_name)
        if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'REGISTER'"
        conn.send("REGISTER")
        if conn.read() != client_global.OK_MSG:
            print "[!][" + now() + "] Server didn't respond to the certificate signing request."
            return
        # send CSR to server
        cert_sign_request_len = len(cert_sign_request)
        conn.send(str(cert_sign_request_len))
        conn.send(cert_sign_request)
        # catch certificate len
        cert_len = int(conn.read())
        mycert = conn.recv(cert_len)
        if not client_global.args.production: print "[+][" + now() + "] Received the signed certificate from the server. I'm storing it for further communications"
        mycert_path = client_global.mycert_dir + os.sep + client_name + ".crt"
        f = open(mycert_path,"w")
        f.write(mycert)
        f.close()
        os.remove(client_global.mycert_dir + os.sep + "sirs-client.csr")
        verify_received_certificate(mycert_path)
        if conn.read() != client_global.OK_MSG:
            print "[!][" + now() + "] Register operation not successful :("
            return
        print "[+][" + now() + "] User \"%s\" successfully registered :)" %(client_name)
        # done with server
    # mutual-TLS: https://en.wikipedia.org/wiki/Mutual_authentication (certificate based)
    else:
        # AUTHENTICATE CODE BLOCK
        if client_global.args.login and registered_status:
            if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'AUTHENTICATE'"
            conn.send("AUTHENTICATE")
            # client-side: mutual_ssl_context IS EQUAL to initial_ssl_context in this first steps, so the same assurances described earlier are given
            mutual_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            mutual_ssl_context.verify_mode = ssl.CERT_REQUIRED
            mutual_ssl_context.check_hostname = True
            # server auth
            mutual_ssl_context.load_verify_locations(client_global.clientside_trustanchor_path)
            # load necessary files to authenticate through the TLS connection (client certificate and private key)
            mycertfile_path = client_global.mycert_dir + os.sep + client_name + ".crt"
            mykeyfile_path = client_global.mycert_dir + os.sep + client_name + ".key"
            try:
                mutual_ssl_context.load_cert_chain(certfile=mycertfile_path, keyfile=mykeyfile_path)
            except IOError:
                client_global.interface_error_msg = "[!][" + now() + "] An error occurred when trying to login as \"%s\". Please verify that you have your private key with you (hopefully present in \"utils/mycerts/%s.key\")." %(client_name, client_name)
                print client_global.interface_error_msg
                return
            # create new ssl socket object based on the set parameters
            mutual_conn = mutual_ssl_context.wrap_socket(conn, server_side=False, server_hostname = "*.sirs-server.org", do_handshake_on_connect=True)
            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Authentication operation not successful :("
                return
            if client_global.args.explicitauth: print "[+][" + now() + "] Successfully authenticated as \"%s\"" %(client_name)
            # not yet done with server (possibly, or else you authenticated your channel just to close it after)
        # LIST FILES (INDIVIDUAL)
        if client_global.args.listindividualfiles:
            mutual_conn = list_my_files(mutual_conn, client_name, tag="Individual-Only")
        # LIST FILES (SHARED)
        if client_global.args.listsharedfiles:
            mutual_conn = list_my_files(mutual_conn, client_name, tag="Shared-Only")
        # TODO: "myprivatefiles" can be another working directory
        # TODO: "mysharedfiles" can be another working directory too
        # TODO: give user the choice to have another working directory
        # SEND CODE BLOCK (CLIENT-SERVER)
        if client_global.args.sendindividualfiles:
            if not verify_individual_location(client_global.args.sendindividualfiles):
                return
            clientside_path = os.path.relpath(client_global.args.sendindividualfiles)
            if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'SEND' (securely sending \"%s\" to the server)." %(clientside_path)
            mutual_conn.send("SEND")
            file_structure = create_file_structure(clientside_path, client_name)
            mutual_conn = send_in_chunks(mutual_conn, file_structure)
            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Send operation not successful :("
                return
            print "[+][" + now() + "] \"%s\" successfully sent :)" %(clientside_path)
        # FETCH CODE BLOCK (SERVER-CLIENT)
        elif client_global.args.fetchindividualfiles:
            if not verify_individual_location(client_global.args.fetchindividualfiles):
                return
            clientside_path = os.path.relpath(client_global.args.fetchindividualfiles)
            if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'FETCH' (securely fetching \"%s\" from the server)." %(clientside_path)
            mutual_conn.send("FETCH")
            mutual_conn.send(clientside_path)
            mutual_conn, file_structure = read_in_chunks(mutual_conn)
            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Fetch operation not successful :("
                return
            print "[+][" + now() + "] \"%s\" successfully fetched :)" %(clientside_path)
            reconstruct_client_files(file_structure, client_global.myprivatefiles_dir, client_name)
        elif client_global.args.deleteindividualfiles:
            if not verify_individual_location(client_global.args.deleteindividualfiles):
                return
            clientside_path = os.path.relpath(client_global.args.deleteindividualfiles)
            if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'DELETE-FILE' (delete \"%s\")." %(clientside_path)
            mutual_conn.send("DELETE-FILE")
            mutual_conn.send(clientside_path)
            if not client_global.args.production: print "[+][" + now() + "] Asking for the deletion of a (private) file or directory stored in the server."
            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Delete operation not successful :("
                return
            print "[+][" + now() + "] \"%s\" successfully deleted :)" %(clientside_path)
        # LIST SERVER USERS
        if client_global.args.listallusers:
            if not client_global.args.production: print "[+][" + now() + "] Client-Server: 'LIST-ALL-USERS'"
            mutual_conn.send("LIST-ALL-USERS")
            mutual_conn, server_users_list = read_in_chunks(mutual_conn)
            print "Server users: %s" %(server_users_list)
        # SHARE FILE WITH ANOTHER USER
        elif client_global.args.share:
            input_path = client_global.args.share
            print "[+][" + now() + "] Client-Server: 'LIST-ALL-USERS'"
            mutual_conn.send("LIST-ALL-USERS")
            mutual_conn, server_users_list = read_in_chunks(mutual_conn)
            print "Server users: %s" %(server_users_list)
            
            # client interaction to determine sharee users
            chosen_users_repr = raw_input("Choose the users you want to share it with (separe them with \",\"): ")

            chosen_sharees_list = chosen_users_repr.split(",")
            chosen_sharees_list = [sanitize_clientname(sharee) for sharee in chosen_sharees_list]
            for chosen_sharee in chosen_sharees_list:
                if chosen_sharee==client_name:
                    print "[!][" + now() + "] You cannot choose yourself (%s). Aborting..." %(client_name) 
                    return
                if chosen_sharee not in server_users_list:
                    print "[!][" + now() + "] You cannot choose someone who isn't registered. Aborting..."
                    return
            filebasename = os.path.basename(input_path)
            input_directory = os.path.dirname(input_path)
            clientside_directory = client_global.mysharedfiles_dir + os.sep + client_name
            chosen_sharees_list = sorted(chosen_sharees_list)
            for chosen_sharee in chosen_sharees_list:
                clientside_directory += "-" + chosen_sharee
            mkdir_p(clientside_directory)
            
            clientside_path = input_path.replace(input_directory, clientside_directory)
            print "[+][" + now() + "] Copying file to \"%s\" directory. Work on that copy from now on as that's where the fetched shared files are going to." %(clientside_directory)
            recursive_copy_cmd = "cp -r " + input_path + " " + clientside_path
            subprocess.check_call(recursive_copy_cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
            print "[+][" + now() + "] Client-Server: 'SHARE' (sharing my files with chosen users)"
            mutual_conn.send("SHARE")
            share_info = [clientside_path, chosen_sharees_list]
            mutual_conn = send_in_chunks(mutual_conn, share_info)
            mutual_conn, user_certs = read_in_chunks(mutual_conn)
            sharedfile_structure = dict()
            sharedfile_structure[clientside_directory] = dict()
            if os.path.isfile(clientside_path):
                sharedfile_structure = sharedfile_prepare(clientside_path, filebasename, user_certs, client_name, sharedfile_structure)
            elif os.path.isdir(clientside_path):
                sharedfile_structure = filestructure_prepare(clientside_path, "not-needed", client_name, sharedfile_structure, user_certs=user_certs, sharedfiles_flag=True)
            else:
                print "[!][" + now() + "] You are trying to send a non-existent file or directory. Aborting..."
                return
            mutual_conn = send_in_chunks(mutual_conn, sharedfile_structure)
            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Share operation not successful :("
                return
            print "[+][" + now() + "] Share successful :)"
            print "[+][" + now() + "] You can now work in \"%s\"." %(clientside_path)
        elif client_global.args.fetchshared:
            mutual_conn = list_my_files(mutual_conn, client_name, tag="Shared-Only")
            if client_global.mysharedfiles_dir not in os.path.commonprefix((os.path.realpath(client_global.args.fetchshared),os.path.abspath(client_global.mysharedfiles_dir))):
                print "[!][" + now() + "] Please provide me with a file or directory inside the \"mysharedfiles\" directory. Aborting..."
                exit()
            clientside_path = os.path.relpath(client_global.args.fetchshared)
            print "[+][" + now() + "] Client-Server: 'FETCH-SHARED' (fetch \"%s\")." %(clientside_path)
            mutual_conn.send("FETCH-SHARED")
            mutual_conn.send(clientside_path)
            mutual_conn, sharedfile_structure = read_in_chunks(mutual_conn)
            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Fetch-shared operation not successful :("
                exit()
            print "[+][" + now() + "] Fetch-shared successful :)"
            reconstruct_client_files(sharedfile_structure, client_global.mysharedfiles_dir, client_name, sharedfiles_flag=True)
        elif client_global.args.sendshared:
            mutual_conn = list_my_files(mutual_conn, client_name, tag="Shared-Only")
            if client_global.mysharedfiles_dir not in os.path.commonprefix((os.path.realpath(client_global.args.sendshared),os.path.abspath(client_global.mysharedfiles_dir))):
                print "[!][" + now() + "] Please provide me with a file or directory inside the \"mysharedfiles\" directory. Aborting..."
                exit()
            clientside_path = os.path.relpath(client_global.args.sendshared)
            filebasename = os.path.basename(clientside_path)
            print "[+][" + now() + "] Client-Server: 'SEND-SHARED' (send \"%s\")." %(clientside_path)
            mutual_conn.send("SEND-SHARED")

            sharedfile_structure = create_file_structure(clientside_path, client_name)
            for directory in sharedfile_structure:
                sharedfile_structure[directory] = dict()
            input_creator_sharees_repr = sharedfile_structure.keys()[0].split(os.sep)[1]
            chosen_sharees_list = input_creator_sharees_repr.split("-")
            share_info = [clientside_path, chosen_sharees_list]

            mutual_conn = send_in_chunks(mutual_conn, share_info)
            mutual_conn, user_certs = read_in_chunks(mutual_conn)

            if os.path.isfile(clientside_path):
                sharedfile_structure = sharedfile_prepare(clientside_path, filebasename, user_certs, client_name, sharedfile_structure)
            elif os.path.isdir(clientside_path):
                sharedfile_structure = filestructure_prepare(clientside_path, "not-needed", client_name, sharedfile_structure, user_certs=user_certs, sharedfiles_flag=True)
            else:
                print "[!][" + now() + "] You are trying to send a non-existent file or directory. Aborting..."
                exit()
            mutual_conn = send_in_chunks(mutual_conn, sharedfile_structure)
            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Send-shared operation not successful :("
                exit()
            print "[+][" + now() + "] Send-shared successful :)"
        # LIST BACKUPS (INDIVIDUAL/SHARED)
        if client_global.args.listmybackups:
            mutual_conn, individual_backups_list, shared_backups_list = list_my_backups(mutual_conn, client_name)
        # REVERT
        elif client_global.args.revert:
            mutual_conn, individual_backups_list, shared_backups_list = list_my_backups(mutual_conn, client_name, "Individual-Only")
            if not individual_backups_list:
                print "[!][" + now() + "] You don't have any individual-backup on the server yet. Aborting..."
                exit()
            chosen_index = raw_input("Please insert the index number of the individual check-point you want to restore: ")
            try:
                chosen_index = int(chosen_index)-1
            except ValueError:
                print "[!][" + now() + "] Please insert an integer. You are trying to insert anything else but a valid index number. Aborting..."
                exit()

            if chosen_index < 0:
                print "[!][" + now() + "] Please insert an integer in the range printed out above. Aborting..."
                exit()
            try:
                chosen_backup_directory = individual_backups_list[chosen_index]
            except IndexError:
                print "[!][" + now() + "] Please insert an integer in the range printed out above. Aborting..."
                exit()

            mutual_conn.send("REVERT")
            mutual_conn = send_in_chunks(mutual_conn, chosen_backup_directory)
            mutual_conn, file_structure_list = read_in_chunks(mutual_conn)
            for file_structure in file_structure_list:
                reconstruct_client_files(file_structure, client_global.myprivatefiles_dir, client_name)

            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Revert-individual operation not successful :("
                exit()
            print "[+][" + now() + "] Revert-individual successful :)"
        elif client_global.args.revertshared:
            mutual_conn, individual_backups_list, shared_backups_list = list_my_backups(mutual_conn, client_name, "Shared-Only")
            if not shared_backups_list:
                print "[!][" + now() + "] You don't have any shared-backup on the server yet. Aborting..."
                exit()
            chosen_index = raw_input("Please insert the index number of the shared check-point you want to restore: ")
            try:
                chosen_index = int(chosen_index)-1
            except ValueError:
                print "[!][" + now() + "] Please insert an integer. You are trying to insert anything else but a valid index number. Aborting..."
                exit()

            if chosen_index < 0:
                print "[!][" + now() + "] Please insert an integer in the range printed out above. Aborting..."
                exit()
            try:
                chosen_backup_directory = shared_backups_list[chosen_index]
            except IndexError:
                print "[!][" + now() + "] Please insert an integer in the range printed out above. Aborting..."
                exit()

            mutual_conn.send("REVERT-SHARED")
            mutual_conn = send_in_chunks(mutual_conn, chosen_backup_directory)
            mutual_conn, file_structure_list = read_in_chunks(mutual_conn)
            for file_structure in file_structure_list:
                reconstruct_client_files(file_structure, client_global.mysharedfiles_dir, client_name, sharedfiles_flag=True)

            if mutual_conn.read() != client_global.OK_MSG:
                print "[!][" + now() + "] Revert-shared operation not successful :("
                exit()
            print "[+][" + now() + "] Revert-shared successful :)"

def run():
    mkdir_p(client_global.mycert_dir)
    mkdir_p(client_global.shareuser_certs_dir)
    mkdir_p(client_global.myprivatefiles_dir)
    mkdir_p(client_global.mysharedfiles_dir)
    client()

class ClientGlobal:
    def __init__(self):
        # =====================
        #     CLI OPTIONS
        # =====================
        self.oparser = argparse.ArgumentParser(description='SIRS Project client interface')
        self.oparser.add_argument('--production', help='turn this option on to surpress output', action='store_true', dest='production')
        self.oparser.add_argument('--explicit-auth', help='turn this option on to get successful authentication attempts output', action='store_true', dest='explicitauth')
        self.oparser.add_argument('-r', '--register', help='register command: requires username', dest='register', default="")     # need to provide new cliente name
        self.oparser.add_argument('-l', '--login', help='login command: requires username', dest='login', default="")     # need to provide client name
        self.oparser.add_argument('-lindivfiles','--list-individualfiles', help='get a list of my currently saved files in the server (individual)', action='store_true', dest='listindividualfiles')
        self.oparser.add_argument('-sindivfiles', '--send-individual', help='send file or directory from default directory: requires path', dest='sendindividualfiles', default="") # (flow from client to server)
        self.oparser.add_argument('-findivfiles', '--fetch-individual', help='fetch file or directory into default directory: requires path', dest='fetchindividualfiles', default="") # (flow from server to client)
        self.oparser.add_argument('-delindiv', '--delete-individual', help='deletes an individual file from the server (backups are maintained)', dest='deleteindividualfiles', default="")
        self.oparser.add_argument('-lsharedfiles','--list-sharedfiles', help='get a list of my currently saved files in the server (shared)', action='store_true', dest='listsharedfiles')
        self.oparser.add_argument('-lusers','--list-all-users', help='get a list of other server users', action='store_true', dest='listallusers')
        self.oparser.add_argument('-share', '--share', help='share a file or directory with a list of existent users (from that point on, work on it in the "mysharedfiles" folder): requires path', dest='share', default='') # (flow from client to server)
        self.oparser.add_argument('-fshared', '--fetch-shared', help='fetch shared files with a list of existent users into the "mysharedfiles" folder: requires path', dest='fetchshared', default='') # (flow from server to client)
        self.oparser.add_argument('-sshared', '--send-shared', help='send shared files with a list of existent users from the "mysharedfiles" folder: requires path', dest='sendshared', default='') # (flow from client to server)
        self.oparser.add_argument('-lbackups', '--list-backups', help='lists backups the client has on the server', action='store_true', dest='listmybackups') # revert specific file (flow from server to client)
        self.oparser.add_argument('-revindiv', '--revert-individual', help='fetches a backup of an individual file', action='store_true', dest='revert') # revert specific file (flow from server to client)
        self.oparser.add_argument('-revshared', '--revert-shared', help='fetches a backup of a shared file', action='store_true', dest='revertshared') # revert specific file (flow from server to client)
        argcomplete.autocomplete(self.oparser)
        self.args = self.oparser.parse_args()
        self.OK_MSG = "OK"
        self.utils_dir = this_script_dirpath + os.sep + "utils"
        self.mycert_dir = self.utils_dir + os.sep + "mycerts"
        self.shareuser_certs_dir = self.mycert_dir + os.sep + "sharee_certs"
        self.myprivatefiles_dir = this_script_dirpath + os.sep + "myprivatefiles"
        self.mysharedfiles_dir = this_script_dirpath + os.sep + "mysharedfiles"
        self.clientside_trustanchor_path = this_script_dirpath + os.sep + "utils" + os.sep + "sirs-ca.crt"
        self.clientside_certificates_trustanchor_path = this_script_dirpath + os.sep + "utils" + os.sep + "sirs-cli-signing-ca.crt"
        self.interface_error_msg = ""
client_global = ClientGlobal()

if __name__=="__main__":
    run()