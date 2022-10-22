from pathlib import Path
from cryptography.fernet import Fernet as fer
from files.code.datarecords import records


class generate():
    def account(self):

        users = records()

        self.account_action = str(input("[1] Login \n[2] Create Account \n> "))

        if self.account_action == '1':
            users.default(self.account_action)
        elif self.account_action == '2':
            users.default(self.account_action)
        else:
            print("WARNING: Invalid input!")
            self.account()
