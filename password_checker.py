from PyQt5.QtWidgets import QApplication, QFormLayout, QMainWindow, QMessageBox, QVBoxLayout, QWidget, QPushButton, QLineEdit, QListWidget
import hashlib
import os

'''
V1.0
 * Username input line
 * Password input line
 * Save button to save Username and Password
 * Check button to check Username and Password

V1.1
 * List Accounts button added - you can list the Usernames
 * Bug fixed: If user file isn't exist create it

V1.2
 * Function of List Accounts button fixed.

'''

# Create the main class
class PasswordChecker(QWidget):

    # Initalize the app's parameters
    def __init__(self, parent = None):
        super(PasswordChecker, self).__init__(parent)
        self.setFixedSize(300, 170)
        self.setWindowTitle("Password Checker")

        
        # We use a dictionary to save the Username and Passwords
        self.useDict() 

        # Initalize the User Interface
        self.initUI()


    #----- Initalize User Interface -----
    def initUI(self):
        
        # Create the Layouts
        vbox = QVBoxLayout() # Main Layout
        form = QFormLayout()

        # Create the input lines
        self.userLine = QLineEdit()
        self.pwdLine = QLineEdit()

        # Set password line to "hidden" as password
        self.pwdLine.setEchoMode(QLineEdit.Password)

        # Create Save button
        buttonSave = QPushButton("Save")
        buttonSave.clicked.connect(lambda: self.saveFunc(self.userLine.text(), self.pwdLine.text()))

        # Create Check button
        buttonCheck = QPushButton("Check")
        buttonCheck.clicked.connect(lambda: self.checkFunc(self.userLine.text(), self.pwdLine.text()))

        # Create the List button
        buttonList = QPushButton("List Usernames")
        buttonList.clicked.connect(self.usersList)

        # Create the FormLayout (row added)
        form.addRow("Username:", self.userLine)
        form.addRow("Password:", self.pwdLine)

        # Add the layouts to mainlayout
        vbox.addLayout(form)
        vbox.addWidget(buttonSave)
        vbox.addWidget(buttonCheck)
        vbox.addWidget(buttonList)
        self.setLayout(vbox)

    #----- Initalize dictionary method -----
    def useDict(self):

        # If user file is already exist
        if not os.path.isfile("users.omg"):
            with open("users.omg", "w") as createFile:
                createFile.write("")
         

        else:

            self.initDict()

    def initDict(self):

        # Create dictionary
        self.users = {}

        # Open the file where the Usernames and Passwords are saved
        with open('users.omg', 'r') as readFile:

            # Load the lines
            for line in readFile:
                text = str(line)

                # Need a counter to initalize the start and end of Usernames and Passwords
                startA = 0
                endA = 0

                # Check the alphabets one-by-one
                for index, a in enumerate(text):
                    
                    # If it finds a ??, then Username ist from startA to endA
                    if a == '??':
                        endA = index
                        userNow = text[startA:endA]
                        startA = index + 1

                    # If it finds a ??, then Passwors ist from startA to endA
                    elif a == '??':
                        endA = index
                        pwdNow = text[startA:endA]
                        startA = index + 1

                        # Put the currently Username and Password to dictionary if there is ?? + ??
                        self.users[userNow] = pwdNow
        
        return self.users
                    
    def returnUsers(self):
        for user in self.users:
            return user


    #----- Password hashing ----->
    def hashPwd(self, pwd):

        # Hash Password by sha256
        hashed = hashlib.sha256()
        hashed.update(pwd.encode('utf-8'))
        self.hashed_pwd = hashed.hexdigest()
        return self.hashed_pwd

    # ----- Method of Save Button -----
    def saveFunc(self, user, pwd):
        
        # Initalize Dictionary (Username, Password)
        self.useDict()

        # Hash Password by sha256
        self.hashPwd(pwd)
        
        #Open file by append mode
        with open("users.omg", "a") as appendFile:

            # Check empty cells
            if user == '' and pwd == '':
                QMessageBox().warning(self, "Warning", "Username and Password are empty!", QMessageBox.Close)
            elif user == '':
                QMessageBox().warning(self, "Warning", "Username is empty!", QMessageBox.Close)
            elif pwd == '':
                QMessageBox().warning(self, "Warning", "Password is empty!", QMessageBox.Close)  
            else:

                # Check if Username with Password already in list
                if user in self.users and self.hashed_pwd in self.users[user]:
                    QMessageBox().warning(self, "Warning", "Username with Password already in list.", QMessageBox().Close)
                elif user in self.users:
                    QMessageBox().warning(self, "Warning", "Username already in the list", QMessageBox.Close)
                
                else:
                    # Write Username and Password in the list if there's no exist.
                    appendFile.write(f'{user}??{self.hashed_pwd}??')
                    QMessageBox().information(self, "Added to the list", f"Username: {user}\nPassword: {pwd}", QMessageBox().Ok)

        # Reset the input lines
        self.userLine.setText("")
        self.pwdLine.setText("")

    # ----- Method of Check Button -----
    def checkFunc(self, user, pwd):

        # Initalize Dictionary (Username, Password)
        self.useDict()
        
        # Hash Password by sha256
        self.hashPwd(pwd)

         # Check empty cells
        if user == '' and pwd == '':
            QMessageBox().warning(self, "Warning", "Username and Password are empty!", QMessageBox.Close)
        elif user == '':
            QMessageBox().warning(self, "Warning", "Username is empty!", QMessageBox.Close)
        elif pwd == '':
            QMessageBox().warning(self, "Warning", "Password is empty!", QMessageBox.Close)  
        else:

            # Check if Username with Password already in list
            if user in self.users and self.hashed_pwd == self.users[user]:
                QMessageBox().question(self, "Found", f"Username: {user}\nPassword: {pwd}", QMessageBox().Ok)
            elif user in self.users and self.hashed_pwd != self.users[user]:
                QMessageBox().warning(self, "Warning", "Incorrect Password", QMessageBox().Close)
            elif user not in self.users:
                QMessageBox().warning(self, "Warning", "Username is not in the list.", QMessageBox().Close)
            else:
                QMessageBox().warning(self, "Warning", "Username and Password are not in the list.", QMessageBox().Close)

        # Reset the input lines
        self.userLine.setText("")
        self.pwdLine.setText("")

    def usersList(self):

        self.userListWindow = UserList(self)
        self.userListWindow.show()
        return self.users

# ----- List of accounts windows -----    
class UserList(QMainWindow):

    def __init__(self, parent = None):
        super(UserList, self).__init__(parent)

        # Set title of window
        self.setWindowTitle("Username list")

        # Set window's width
        self.setFixedWidth(300)

        # Make object from QListWidget
        self.usersList = QListWidget()

        # Set the object as central widget
        self.setCentralWidget(self.usersList) 

        # Initalize Dictionary in UserList
        self.initDict()


    #----- Initalize dictionary method -----
    def initDict(self):
    
        # Create dictionary
        self.users = {}

        # Open the file where the Usernames and Passwords are saved
        with open('users.omg', 'r') as readFile:

            # Load the lines
            for line in readFile:
                text = str(line)

                # Need a counter to initalize the start and end of Usernames and Passwords
                startA = 0
                endA = 0

                # Check the alphabets one-by-one
                for index, a in enumerate(text):
                    
                    # If it finds a ??, then Username ist from startA to endA
                    if a == '??':
                        endA = index
                        userNow = text[startA:endA]
                        startA = index + 1

                    # If it finds a ??, then Passwors ist from startA to endA
                    elif a == '??':
                        endA = index
                        pwdNow = text[startA:endA]
                        startA = index + 1

                        # Put the currently Username and Password to dictionary if there is ?? + ??
                        self.users[userNow] = pwdNow
        
        # Search files
        for user in self.users:
            self.usersList.addItem(user)


# Rund the app if it' the main window
if __name__ == "__main__":

    import sys
    app = QApplication(sys.argv)
    window = PasswordChecker()
    window.show()

    # This parameter need for clear exit
    sys.exit(app.exec_())


