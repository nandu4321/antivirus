import sys
import os
from PyQt5.QtWidgets import QMainWindow,QApplication,QPushButton,QFileDialog
from PyQt5.QtCore import pyqtSignal,QFile,QTextStream
from os import mkdir
from mpui import *
import hashlib
from cryptography.fernet import Fernet
from PyQt5.QtGui import QIcon
import fullscanfn


virusnamewithtype=[]
virusname = []

class MainWindow(QMainWindow):

    def  __init__(self):
        super(MainWindow,self).__init__()
        try:
            if not os.path.exists(r'C:miniproject2'):
                os.mkdir(r'C:\miniproject2')
                os.mkdir(r'C:\miniproject2\storage')
                f=open(r'C:\miniproject2\storage\date.txt','w')
                f.close()
                f=open(r'C:\miniproject2\storage\password.txt','w')
                f.close()
        except OSError:
            pass

        self.setWindowIcon(QIcon("shield.png"))
        self.ui=Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("DefendX")

        self.ui.icononlywidget.hide()
        self.ui.stackedWidget.setCurrentIndex(0)
        self.ui.threelinebtn.setChecked(True)
        #when a side button clicked
        self.ui.scanbtn1.clicked.connect(self.when_scanbtn_clicked)
        self.ui.vaultbtn1.clicked.connect(self.when_valutbtn_clicked)
        # self.ui.updatebtn1.clicked.connect(self.when_updatebtn_clicked)
        self.ui.settingsbtn1.clicked.connect(self.when_settingsbtn_clicked)
        # self.ui.updatebtn1.clicked.connect(self.when_updatebtn_clicked)
        # self.ui.infobtn1.clicked.connect(self.when_infobtn_clicked)
        self.ui.scanbtn2.clicked.connect(self.when_scanbtn_clicked)
        self.ui.vaultbtn2.clicked.connect(self.when_valutbtn_clicked)
        # self.ui.updatebtn2.clicked.connect(self.when_updatebtn_clicked)
        self.ui.settingsbtn2.clicked.connect(self.when_settingsbtn_clicked)
        # self.ui.updatebtn2.clicked.connect(self.when_updatebtn_clicked)
        # self.ui.infobtn1_2.clicked.connect(self.when_infobtn_clicked)
        #when change
        self.ui.passwordbtn.clicked.connect(self.when_passwordbtn_clicked)

        #settings new password
        self.ui.password_confirmbtn1.clicked.connect(self.passfn)

        #settings edit password
        self.ui.change_passwordbtn1.clicked.connect(self.edit_password)

        self.ui.edit_password_confimbtn.clicked.connect(self.when_changepassword_confirmbtn_clicked)

        self.ui.vallt_password_confirm.clicked.connect(self.password_vault_compare)

        #valutlock
        self.ui.vault_lock_addfilrbtn.clicked.connect(self.when_vault_lockaddfile_clicked)
        self.ui.vault_lock_retrivefilebtn.clicked.connect(self.when_vault_lock_retrivefilebtnclicked)
        self.print_listwidget_status = True


        # #scab btn clicked
        # self.ui.scan_button.clicked.connect(self.when_scan_button_clicked)

        self.ui.normal_file_scanbtn.clicked.connect(self.when_normal_file_scan_clicked)
        self.ui.advanced_file_scanbtn.clicked.connect(self.when_advanced_file_scan_clicked)
        self.ui.normal_file_scan_select.clicked.connect(self.when_normal_file_scanbtn_clicked)
        self.ui.advanced_scan_selectbtn.clicked.connect(self.when_advancedscan_selectbtn_clicked)
        self.ui.full_scan_btn.clicked.connect(self.when_full_scan_stacked)
        self.ui.full_scanbtn.clicked.connect(self.when_fullscanbtn_clicked)
        if os.stat(r"C:\miniproject2\storage\password.txt").st_size!=0:
            with open(fr'C:\miniproject2\storage\k.key', 'rb') as filekey:
                key = filekey.read()
            fernet = Fernet(key)
            with open(fr'C:\miniproject2\storage\password.txt', 'rb') as enc_file:
                encrypted = enc_file.read()
            decrypted = fernet.decrypt(encrypted)
            self.main_password=decrypted.decode('utf-8')

    def when_advancedscan_selectbtn_clicked(self):
        try:
            open_file = QFileDialog.getExistingDirectory()
            malware_hashes = list(open("DataBase\\HashDataBase\\Sha256\\virusHash.unibit", 'r').read().split('\n'))
            virusinfo = list(open("DataBase\\HashDataBase\\Sha256\\virusInfo.unibit", 'r').read().split('\n'))

            def sha256_hash(filename):
                import hashlib
                try:
                    with open(filename, "rb") as f:
                        bytes = f.read()
                        sha256hash = hashlib.sha256(bytes).hexdigest()

                        f.close()
                    return sha256hash
                except:
                    return 0

            def malware_checker(pathoffile):
                hash_malware_check = sha256_hash(pathoffile)
                counter = 0

                for i in malware_hashes:
                    if i == hash_malware_check:
                        return virusinfo[counter]
                    counter += 1

                return 0


            def folder_scanner():
                path = fr"{open_file}"
                dir_list = list()
                for (dirpath, dirnames, filenames) in os.walk(path):
                    dir_list += [os.path.join(dirpath, file) for file in filenames]
                for i in dir_list:

                    print(i)
                    if malware_checker(i) != 0:
                        virusname.append(i)
                        os.remove(i)
                    #     name_of_fileinstr = ""
                    #     for ele in virusname:
                    #         name_of_fileinstr += ele


            folder_scanner()
            print(virusname)
            def Enquiry(lis1):
                if len(lis1) == 0:
                    return 0
                else:
                    return 1
            lis1 = []
            if Enquiry(virusname):
                self.ui.advanced_scan_notification2.setText('VIRUS DETECTED')
            else:
                self.ui.advanced_scan_notification2.setText('NO VIRUS DETECTED')
        except FileNotFoundError:
            pass

    def when_fullscanbtn_clicked(self):
        try:
            malware_hashes = list(open("DataBase\\HashDataBase\\Sha256\\virusHash.unibit", 'r').read().split('\n'))
            virusinfo = list(open("DataBase\\HashDataBase\\Sha256\\virusInfo.unibit", 'r').read().split('\n'))

            def sha256_hash(filename):
                import hashlib
                try:
                    with open(filename, "rb") as f:
                        bytes = f.read()
                        sha256hash = hashlib.sha256(bytes).hexdigest()

                        f.close()
                    return sha256hash
                except:
                    return 0

            def malware_checker(pathoffile):
                hash_malware_check = sha256_hash(pathoffile)
                counter = 0

                for i in malware_hashes:
                    if i == hash_malware_check:
                        return virusinfo[counter]
                    counter += 1

                return 0


            def folder_scanner():
                path = r"C:\Users"
                dir_list = list()
                for (dirpath, dirnames, filenames) in os.walk(path):
                    dir_list += [os.path.join(dirpath, file) for file in filenames]
                for i in dir_list:

                    print(i)
                    if malware_checker(i) != 0:
                        virusnamewithtype.append(malware_checker(i) + "  in  " + i)
                        virusname.append(i)
                        os.remove(i)
                        self.viruscount+=1
                        name_of_fileinstr = ""
                        for ele in virusname:
                            name_of_fileinstr += ele


            folder_scanner()
            print(virusname)
            print(virusnamewithtype)
            def Enquiry(lis1):
                if len(lis1) == 0:
                    return 0
                else:
                    return 1
            lis1 = []
            if Enquiry(virusname):
                self.ui.label_3.setText('VIRUS DETECTED')
            else:
                self.ui.label_3.setText('NO VIRUS DETECTED')
        except FileNotFoundError:
            pass


    def when_normal_file_scanbtn_clicked(self):
        try:
            self.ui.normal_file_scan_notification.clear()
            open_normal_file_scan = QFileDialog.getOpenFileNames()
            open_filename = open_normal_file_scan[0]
            name_of_fileinstr = ""
            for ele in open_filename:
                name_of_fileinstr += ele
            print(name_of_fileinstr)
            def md5_hash(filename):
                with open(filename, 'rb') as f:
                    bytes = f.read()
                    md5hash = hashlib.md5(bytes).hexdigest()
                    f.close()
                return md5hash

            def malware_finder_md5(pathoffile):
                hash_malware_check = md5_hash(pathoffile)
                malware_hashes = open("DataBase\\HashDataBase\\Md5\\md5HashOfVirus.txt", 'r')
                malware_hashes_read = malware_hashes.read()
                malware_hashes.close()
                if malware_hashes_read.find(hash_malware_check) != -1:
                    self.ui.normal_file_scan_notification.setText("VIRUS DETECTED")
                else:
                    self.ui.normal_file_scan_notification.setText("NO VIRUS DETECTED")
            malware_finder_md5(fr"{name_of_fileinstr}")
        except FileNotFoundError:
            pass
    def when_vault_lock_retrivefilebtnclicked(self):
        try:
            open_file=QFileDialog.getExistingDirectory()
            choosen_file_name=self.ui.listWidget.currentItem().text()
            index_of_text=int(self.ui.listWidget.currentRow())+1
            with open(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}key', 'rb') as filekey:
                key = filekey.read()
            fernet = Fernet(key)
            with open(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}txt', 'rb') as enc_file:
                encrypted = enc_file.read()
            decrypted = fernet.decrypt(encrypted)
            with open(fr'{open_file}/{choosen_file_name}', 'wb') as dec_file:
                dec_file.write(decrypted)
            current_row=self.ui.listWidget.currentRow()
            self.ui.listWidget.takeItem(current_row)
            os.remove(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}key')
            os.remove(fr'C:\miniproject2\storage\{choosen_file_name.rstrip(choosen_file_name[-3:])}txt')
            with open(fr'C:\miniproject2\storage\data.txt', 'r') as data:
                lines=data.readlines()
                ptr=1
                with open(fr'C:\miniproject2\storage\data.txt', 'w') as delete_data:
                    for line in lines:
                        if ptr !=int(index_of_text):
                            delete_data.write(line)
                        ptr+=1
        except FileNotFoundError:
            pass

    def when_vault_lockaddfile_clicked(self):
        try:
            self.open_file_name = QFileDialog.getOpenFileNames()
            list_openfilename = self.open_file_name[0]
            self.name_of_file = ""
            for ele in list_openfilename:
                self.name_of_file += ele
            g=self.name_of_file.split("/")
            self.abosolute_name_of_file=g[-1]

            with open(fr'C:\miniproject2\storage\data.txt','at') as self.store_data:
                self.store_data.write(f"{self.name_of_file}\n")
                self.ui.listWidget.addItem(self.abosolute_name_of_file)
            with open(r"C:\miniproject2\storage\data.txt", 'r') as fp:
                self.no_of_lines = len(fp.readlines())

            y=fr'C:\miniproject2\storage\{self.abosolute_name_of_file.rstrip(self.abosolute_name_of_file[-3:])}txt'

            key = Fernet.generate_key()
            with open(fr'C:\miniproject2\storage\{self.abosolute_name_of_file.rstrip(self.abosolute_name_of_file[-3:])}key', 'wb') as filekey:
                filekey.write(key)
            with open(fr'C:\miniproject2\storage\{self.abosolute_name_of_file.rstrip(self.abosolute_name_of_file[-3:])}key', 'rb') as filekey:
                key = filekey.read()
            fernet = Fernet(key)
            with open(self.name_of_file, 'rb') as file:
                original = file.read()
            encrypted = fernet.encrypt(original)
            with open(y, 'wb') as encrypted_file:
                encrypted_file.write(encrypted)
            os.remove(self.name_of_file)
        except FileNotFoundError:
            pass





    def on_stackedwidget_currentchanged(self,index):
        btn_list=self.ui.icononlywidget.find(QPushButton) \
                    + self.ui.fullmenuwidget.findChildren(QPushButton)
        for btn in btn_list:
            if index in[4,5]:
                btn.setAutoExclusive(False)
                btn.setChecked(False)
            else:
                btn.setAutoExclusive(True)
    def password_vault_compare(self):
        if os.stat(r"C:\miniproject2\storage\password.txt").st_size==0:
            self.ui.vault_password_notification.setText("Set A Password")
            self.ui.vault_password_notification.clear()
        else:
            password=self.ui.vault_password_linedit.text()
            if password==self.main_password:
                self.ui.stackedWidget.setCurrentIndex(7)
                self.ui.vault_password_linedit.clear()
                if self.print_listwidget_status:
                    with open(fr'C:\miniproject2\storage\data.txt', 'rt') as myline:
                        count = 0
                        for line in myline:
                            count += 1
                            g = line.split("/")
                            second_name = g[-1]
                            self.ui.listWidget.addItem(second_name.strip())
                    self.print_listwidget_status=False
            else:
                self.ui.vault_password_notification.setText("Wrong Password")
                self.ui.vault_password_linedit.clear()
    def when_scanbtn_clicked(self):
         self.ui.stackedWidget.setCurrentIndex(0)
    def when_valutbtn_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(1)
    def when_settingsbtn_clicked(self):
        self.ui.stackedWidget.setCurrentIndex(3)
        self.ui.edit_password_notification.clear()
    def when_full_scan_stacked(self):
        self.ui.stackedWidget_2.setCurrentIndex(2)
        self.ui.label_3.clear()
    def when_normal_file_scan_clicked(self):
        self.ui.stackedWidget_2.setCurrentIndex(0)
        self.ui.normal_file_scan_notification.clear()

    def when_advanced_file_scan_clicked(self):
        self.ui.stackedWidget_2.setCurrentIndex(1)
        self.ui.advanced_scan_notification2.clear()
    def when_passwordbtn_clicked(self):
        if os.stat(r"C:\miniproject2\storage\password.txt").st_size==0:
            self.ui.stackedWidget.setCurrentIndex(5)
            self.ui.new_passwordbar.clear()
            self.ui.password_confirmbar.clear()
            self.ui.password_notificationbtn1.clear()
        else:
            self.ui.edit_password_notification.setText("There is an exsisting password")
    def passfn(self):
        password1=self.ui.new_passwordbar.text()
        password2=self.ui.password_confirmbar.text()
        self.ui.new_passwordbar.clear()
        self.ui.password_confirmbar.clear()
        self.ui.password_notificationbtn1.clear()

        if password1==password2:
            n = len(password2)
            hasLower = False
            hasUpper = False
            hasDigit = False
            specialChar = False
            haslenth=False
            normalChars = "abcdefghijklmnopqrstu"
            "vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 "
            for i in range(n):
                if password2[i].islower():
                    hasLower = True
                if password2[i].isupper():
                    hasUpper = True
                if password2[i].isdigit():
                    hasDigit = True
                if password2[i] not in normalChars:
                    specialChar = True
            if (hasLower and hasUpper and
                hasDigit and specialChar and n >= 8):
                self.ui.password_confirmbar.clear()
                self.ui.new_passwordbar.clear()
                self.ui.passwordbtn.disconnect()
                self.ui.password_notificationbtn1.clear()
                self.ui.stackedWidget.setCurrentIndex(3)
                self.ui.edit_password_notification.setText("Password has been added")
                with open(r"C:\miniproject2\storage\password.txt",'w') as psw:
                    psw.write(password2)
                key = Fernet.generate_key()
                with open(fr'C:\miniproject2\storage\k.key', 'wb') as filekey:
                    filekey.write(key)
                with open(fr'C:\miniproject2\storage\k.key', 'rb') as filekey:
                    key = filekey.read()
                fernet = Fernet(key)
                with open(fr'C:\miniproject2\storage\password.txt', 'rb') as file:
                    original = file.read()
                encrypted = fernet.encrypt(original)
                with open(fr'C:\miniproject2\storage\password.txt', 'wb') as encrypted_file:
                    encrypted_file.write(encrypted)
                self.main_password=password2
            elif ((hasLower or hasUpper) and
                  specialChar and n >= 6):
                self.ui.password_notificationbtn1.clear()
                self.ui.password_notificationbtn1.setText("Weak Password")
                self.ui.new_passwordbar.clear()
                self.ui.password_confirmbar.clear()
            else:
                self.ui.password_notificationbtn1.clear()
                self.ui.password_notificationbtn1.setText("Weak Password")
                self.ui.new_passwordbar.clear()
                self.ui.password_confirmbar.clear()
        else:
            self.ui.password_notificationbtn1.clear()
            self.ui.password_notificationbtn1.setText("Password Mismatch")
            self.ui.new_passwordbar.clear()
            self.ui.password_confirmbar.clear()

    def edit_password(self):
        if os.stat(r"C:\miniproject2\storage\password.txt").st_size != 0:
            self.ui.stackedWidget.setCurrentIndex(6)
            self.ui.edit_password_notification.clear()
            self.ui.previos_password_lineedit.clear()
            self.ui.newpassword_lineedit.clear()
            self.ui.confirm_password_lineedit.clear()
        else:
            self.ui.edit_password_notification.setText("Set a new password")

    def when_changepassword_confirmbtn_clicked(self):
        previous_password=self.ui.previos_password_lineedit.text()
        new_password1=self.ui.newpassword_lineedit.text()
        new_password2=self.ui.confirm_password_lineedit.text()
        try:
            if os.stat(r"C:\miniproject2\storage\password.txt").st_size==0:
                self.ui.edit_password_notification_2.setText("Set A Password")
            elif self.main_password!=previous_password:
                self.ui.edit_password_notification_2.setText("Previous passowrod is not matching")
            elif new_password1!=new_password2:
                self.ui.edit_password_notification_2.setText("Not matching")
            elif self.main_password==new_password2:
                self.ui.edit_password_notification_2.setText("Change the current password")
            elif  len(new_password2)<8:
                self.ui.edit_password_notification_2.setText("Password Should be above 7 characters ")
            else:
                if previous_password==self.main_password and new_password1==new_password2:
                    n = len(new_password2)
                    hasLower = False
                    hasUpper = False
                    hasDigit = False
                    specialChar = False
                    haslenth = False
                    normalChars = "abcdefghijklmnopqrstu"
                    "vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 "
                    for i in range(n):
                        if new_password2[i].islower():
                            hasLower = True
                        if new_password2[i].isupper():
                            hasUpper = True
                        if new_password2[i].isdigit():
                            hasDigit = True
                        if new_password2[i] not in normalChars:
                            specialChar = True
                    if (hasLower and hasUpper and
                            hasDigit and specialChar and n >= 8):
                        with open(r"C:\miniproject2\storage\password.txt", 'w') as psw:
                            psw.write(new_password2)
                        self.main_password=new_password2
                        self.ui.edit_password_notification.setText("Password has been modified")

                        self.ui.stackedWidget.setCurrentIndex(3)
                        key = Fernet.generate_key()
                        with open(fr'C:\miniproject2\storage\k.key', 'wb') as filekey:
                            filekey.write(key)
                        with open(fr'C:\miniproject2\storage\k.key', 'rb') as filekey:
                            key = filekey.read()
                        fernet = Fernet(key)
                        with open(fr'C:\miniproject2\storage\password.txt', 'rb') as file:
                            original = file.read()
                        encrypted = fernet.encrypt(original)
                        with open(fr'C:\miniproject2\storage\password.txt', 'wb') as encrypted_file:
                            encrypted_file.write(encrypted)

                    else:
                        self.ui.edit_password_notification_2.setText("Weak password")
                        self.ui.confirm_password_lineedit.clear()
                        self.ui.newpassword_lineedit.clear()
                        self.ui.previos_password_lineedit.clear()
        except ConnectionError:
            pass

if __name__=="__main__":
    app=QApplication(sys.argv)
    window=MainWindow()
    window.show()
    sys.exit(app.exec_())


