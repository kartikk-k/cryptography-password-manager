import gspread
from pathlib import Path
from cryptography.fernet import Fernet as fer
import base64
import os



class records():
    def default(self, account, credentials_path='/home/rayhacks/Desktop/vscode/python/cryppass/files/api/credentials.json'):
        # print('running records.py')
        self.filepath = Path(
            '/home/rayhacks/Desktop/vscode/python/CrypPassword Generator/files/api/credentials.json')
        self.filepath = credentials_path
        self.account = account

        global gc
        gc = gspread.service_account(filename=self.filepath)
        global user_creds, user_pass
        user_creds = gc.open('User-credentials')
        user_pass = gc.open('Py-db')

        if self.account == '1':
            self.login()
        else:
            self.create_account()

    def create_account(self):
        # getting worksheet data
        worksheet = user_creds.sheet1
        pass_worksheet = user_pass

        print('Enter details:')
        unique_id = True

        # checking username availability
        while unique_id == True:
            username = str(input("Username: "))

            user_id = worksheet.find(username)
            unique_id = bool(user_id)

            if unique_id == False:
                print('Username available!')
            else:
                print('Username not available \nChoose another username ')

        email_id = str(input("Email id: "))
        name = str(input("Name: "))

        # confirming details
        confirm = str(input("Confirm details [Y] Yes [N] No \n> "))
        if confirm == 'y' or confirm == 'Y':
            row_count = len(worksheet.col_values(1))

            # generating hash key for new user
            key = fer.generate_key()
            f = fer(key)
            username_byte = bytes(username, 'utf-8')
            token = f.encrypt(username_byte)

            # saving hash file in local storage
            self.primary_key(key, username, function='creating_account')

            # storing user details and creating user passwords sheet
            update = worksheet.update(
                f'A{row_count+1}:D{row_count+1}', [[username, email_id, name, token]])
            usersheet = pass_worksheet.add_worksheet(
                username, rows=1000, cols=26)
            fab = usersheet.update(
                'A1:E1', [['website/app', 'username', 'email', 'key', 'token']])
            print("Account Created")
            self.login()

        elif confirm == 'n' or confirm == 'N':
            print("Re-enter details!")
            self.create_account()

    def primary_key(self, key, username, function, token=None):
        self.function = function
        self.token = token
        if self.function == 'creating_account':
            self.key = key
            username_bytes = bytes(username, 'utf-8')
            unique_key = (self.key+username_bytes)
            str_key = bytes.decode(unique_key)
            path = Path('files/keys')
            key_path = Path('files/keys/key.txt')
            # checking for path existence
            if path.exists():
                # print('Path exists')
                if key_path.exists():
                    pass
                else:
                    Path('key.txt').touch()
            else:
                print('Path does not exists')
                path = Path('files/keys')
                path.mkdir()

            key_path.open('w').write(str_key)
            auth_check = False
        elif self.function == 'login':
            path = Path('files/keys/key.txt')

            key = bytes(path.open('r').read(), 'utf=8')
            f = fer(key)
            # token to be fetched
            token = (self.token)
            try:
                f.decrypt(token)
                # print('success')
                auth_check = True
            except:
                auth_check = False
                print('Ivalid key')
        return auth_check

    def login(self, username=None):
        worksheet = user_creds.sheet1
        self.username = username

        print("Login to your account")
        if self.username == None:
            access_denied = True

            while access_denied == True:
                self.username = str(input("Enter your username:\n> "))
                user_id = worksheet.find(self.username)
                id_found = bool(user_id)

                if id_found == False:
                    print('WARNING: Username not found!')
                    denied_action = str(
                        input("[1] Retry \n[2] Create new account \n>"))
                    if denied_action == '1':
                        pass
                    elif denied_action == '2':
                        access_denied = True
                        self.create_account()
                    else:
                        print("WARNING: Enter valid input!")
                        self.login()
                elif id_found == True:
                    # getting row,col for cell with token-id
                    token_cell = worksheet.cell(user_id.row, 4).value
                    token = bytes(token_cell, 'utf=8')
                    access_denied = False

        auth_check = self.primary_key(
            key=None, username=self.username, function='login', token=token)

        # checking login access
        login_access = bool(id_found & auth_check)
        if login_access == True:
            print("Logged in:\n")
            pass_list = user_pass.worksheet(self.username)

            account_action = str(input(
                "Select to continue: \n[1] Add password \n[2] View password \n[3] Open settings \n> "))
            valid_input = False
            while valid_input == False:
                if account_action == '1':
                    valid_input = True
                    self.add_password(pass_list)
                elif account_action == '2':
                    valid_input = True
                    self.view_passwords(pass_list)
                elif account_action == '3':
                    # function to be added
                    self.open_settings()
                    valid_input = True
                else:
                    print("WARNING: Enter valid input!")
        else:
            print(
                "LOGIN ERROR: Check if key.txt are present in keys folder or check username.")
            error_input = False
            while error_input == False:
                login_error_action = str(
                    input("[1] Retry login\n[2] Create account\n> "))
                if login_error_action == '1':
                    self.login()
                elif login_error_action == '2':
                    self.create_account()
                else:
                    print("WARNING: Enter valid input!")

    def add_password(self, pass_list):
        self.pass_list = pass_list
        web_app = self.pass_list.col_values(1)
        row_count = len(web_app)
        self.path = Path('files/keys/key.txt')
        self.key = bytes(self.path.open('r').read(), 'utf-8')

        print("Adding new password: \n")

        website_app = str(input("Website/app: "))
        username = str(input("Username: "))
        email_id = str(input("Email-id: "))

        pass_created = False

        while pass_created == False:
            password_option = str(
                input("Password: [1] Auto generate [2] Custom: "))
            if password_option == '1':
                print("Auto generating password: ")
                password = base64.urlsafe_b64encode(os.urandom(16))
                print(password)
                new_key = fer.generate_key()
                print(f'new key: {new_key}')
                key = self.key + new_key
                print(f'key: {key}')
                f = fer(key)

                # bytes_password = bytes(password, 'utf-8')
                # print(bytes_password)
                token = f.encrypt(password)
                pass_created = True
            elif password_option == '2':
                # add minimum length logic / add while loop to avoid repeatation of process
                custom_pass = str(input("Enter password: "))
                password = bytes(custom_pass, 'utf-8')
                new_key = fer.generate_key()
                key = self.key + new_key
                f = fer(key)
                token = f.encrypt(password)
                pass_created = True
            else:
                print("WARNING: Enter valid input!")

        adding_password = self.pass_list.update(
            f'A{row_count+1}:E{row_count+1}', [[website_app, username, email_id, new_key, token]])

        next_action = str(input("[1] View passwords \n[2] Add another\n"))
        if next_action == '1':
            self.view_passwords(self.pass_list)
        elif next_action == '2':
            self.add_password(self.pass_list)
        else:
            self.login()

        # encrypting password
        # self.encryp_pass()

    def view_passwords(self, pass_list):
        self.pass_list = pass_list
        record_count = len(self.pass_list.col_values(1))

        options = str(input("[1] View all records \n[2] Search record \n> "))
        if options == '1':
            col_count = 2
            print('\nSearch Results: ')
            while col_count <= record_count:
                record_list = self.pass_list.row_values(col_count)
                # decryption
                key = record_list[3]
                token = record_list[4]
                password = self.decrypt_pass(key, token)

                print(
                    f'{col_count-1}.\n Website/app: {record_list[0]}\n Username: {record_list[1]}\n Email id: {record_list[2]}\n Password: {password}\n')
                col_count += 1
        elif options == '2':
            search_pass = str(input("Enter website or app name: \n> "))
            search_record_cell = pass_list.findall(search_pass)
            length_check = len(search_record_cell)
            print(length_check)
            duplicate_count = 0

            print("\nSearch results: \n")
            print(f'Duplicate results: {length_check-1}\n')

            while duplicate_count < length_check:
                search_record_row = search_record_cell[duplicate_count].row
                search_results = self.pass_list.row_values(search_record_row)

                key = search_results[3]
                token = search_results[4]
                password = self.decrypt_pass(key, token)
                # password decryption logic
                print(
                    f'{duplicate_count+1} \n Website/app: {search_results[0]}\n Username: {search_results[1]}\n Email id: {search_results[2]}\n Password: {password}\n')
                # print(search_record_row)
                duplicate_count += 1
        else:
            print("WARNING: Enter valid input!")
            self.view_passwords(self.pass_list)

    def decrypt_pass(self, key, token):
        self.key = bytes(key, 'utf-8')
        self.token = bytes(token, 'utf-8')
        path = Path('files/keys/key.txt')
        user_key = bytes(path.open('r').read(), 'utf-8')

        key = user_key + self.key
        f = fer(key)

        password = bytes.decode(f.decrypt(self.token))

        return password
