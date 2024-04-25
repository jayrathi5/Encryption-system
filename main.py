import ast
import json
import random
import string
from kivy.clock import Clock
import threading
from kivy.app import App
from kivy.lang import Builder
from kivy.properties import StringProperty
from kivy.uix.screenmanager import ScreenManager, Screen
from tkinter import Tk
from tkinter.filedialog import askopenfilenames
from tkinter.filedialog import asksaveasfilename
from CipherText import *
from email_function import *
import datetime
import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
from e import *


#========================
First_Name = ''
Last_Name = ''
Email = ''
Phone = ''
Password = ''
OTP = ''
otp_time = datetime.datetime.now()
#========================



class Window_manager(ScreenManager):
    pass
class Registration_success(Screen):
    pass



class Forgot_Password(Screen):

    def send_otp(self):
        self.ids.error.text = ''
        if self.check_email():
            th  = threading.Thread(target=self.otp_sender,args=(self.ids.mail.text,))
            th.start()
            self.ids.error.text = "Sending Otp ... PLease Wait :)"
            self.ids.otp.disabled = False
        else:
            self.ids.error.text = "Email Id Not register with us ..  :("



    def check_email(self):
        data = ""
        try:
            file = open("user.txt","r")
            data = file.read()
            file.close()
        except:
            pass

        if data == "":
            return False
        else:
            data = json.loads(data)
            if self.ids.mail.text in data:
                return True
        return False

    def resend_otp(self):
        th = threading.Thread(target=self.otp_sender, args=(self.ids.mail.text,))
        th.start()
        self.ids.error.text = "Sending Otp ... PLease Wait :)"

    def otp_validation(self):
        e_otp = self.ids.otp.text

        if len(e_otp) == 10:

            if e_otp == OTP:
                if otp_time_checker() :
                    self.manager.current = "cp"
                else:
                    self.ids.error.text = "Time Over ! Request For New OTP "

            else:
                self.ids.error.text = "INVALID OTP"
        else:
            self.ids.error.color = "red"
            self.ids.error.text = "Wrong Otp Enters"


    def otp_sender(self, mail):
        global otp_time
        Otp_maker()
        sub = "Otp for Changing Password in Data Encryptor/Decryptor "
        message = \
            f'''
       This is your OTP for Changing the Password of Account register into the Data Encryptor / Decryptor
       Otp  : {OTP} 
       
       Otp is valid for only 60 sec 
       Please do not share the otp for the security purpose 

       Thanks  
               '''
        try:
            send_email(mail, sub, message)
            otp_time = datetime.datetime.now()
            self.ids.error.text = "Otp sent Successfully :)"
            self.ids.resend.disabled = False
            return True
        except Exception as e:
            self.ids.error.text = "\tSomething went wrong :( \n Check Your Mail Id or Internet Connection "
            return False



class Change_Password(Screen):


    def Check_Password(self):
        if self.password_checking(self.ids.pas.text):
            if self.ids.pas.text == self.ids.cpass.text :
                self.change_pass()
            else:
                self.ids.error.text = "Password and Confirm Password Should Match"
        else:
            self.ids.error.text = f'''{" "*60}Invalid Password :)
            Password Should Contain Number and Special Character and 10 letters long'''

    def change_pass(self):
        mail = self.manager.screens[9].mail.text
        try:
            file = open("user.txt","r")
            data = file.read()
            file.close()
            dict = json.loads(data)
            dict[mail]['password'] = self.ids.pas.text

            with open("user.txt","w") as f:
                f.write(json.dumps(dict))
            self.manager.screens[9].mail.text = ""
            self.manager.screens[9].otp.text = ""
            self.manager.screens[9].error.text = ""

            self.manager.current = "pas_change"
        except Exception as e:
            self.ids.error.text = "Unable To change the password :( "

    def password_checking(self, string):

        special_charcetrs = "!@#$%^&*?/~"
        num = "1234567890"
        chr = "abcdefghijklmnopqrstuvwxyz"
        x = False
        y = False
        z = False
        if len(string) >= 10:
            for i in special_charcetrs:
                if i in string:
                    x = True
                    break

            for i in special_charcetrs:
                if i in string:
                    y = True
                    break

            for i in chr:
                if i in string or i.upper() in string:
                    z = True
                    break

            if x and y and z:
                return True
            else:
                return False


        else:
            return False


class Sucess_password(Screen):
    pass

def update_data(x):
    global Email
    Email = x

class Login_screen(Screen):

    def check_data(self):
        id = self.ids.username.text
        password = self.ids.password.text

        if id == "" or password == "":
            self.ids.error.text = 'Fill All the Fields :('
        else:
            if not self.found_username():
                self.ids.error.text = "Id is not Register :( "
            else:
                if not self.find_password():
                    self.ids.error.text = "Wrong Password Enter :( "
                else:
                    update_data(self.ids.username.text)
                    self.ids.username.text = ""
                    self.ids.password.text = ""
                    self.ids.error.text = ""
                    self.manager.current = "signin"


    def found_username(self):
        data = ""
        try:
            file = open("user.txt", "r")
            data = file.read()
            file.close()
        except:
            pass

        if data == "":
            return False
        else:
            data = json.loads(data)
            if self.ids.username.text in data:
                return True
        return False

    def find_password(self):
        data = ""
        try:
            file = open("user.txt", "r")
            data = file.read()
            file.close()
        except:
            pass

        if data == "":
            return False
        else:
            data = json.loads(data)
            if self.ids.username.text in data:
                if self.ids.password.text == data[self.ids.username.text]['password']:
                    return True
        return False




    def forgot_password(self):
        pass

class Signed_screen(Screen):
    pass


def randStr(chars=string.ascii_uppercase + string.digits, N=10):
    return ''.join(random.choice(chars) for _ in range(N))


def Otp_maker():
    global OTP
    OTP = randStr()




def otp_time_checker():
    global otp_time
    if datetime.datetime.now() < otp_time + datetime.timedelta(minutes=1.5):
        return True
    else:
        return False
        # return True

class Otp_screen(Screen):

    def Register(self):
        if self.password_checking(self.ids.pas.text):
            if self.ids.pas.text == self.ids.cpass.text:
                self.manager.current = 'success'
                self.Register_data()
                self.manager.screens[1].fn.text = ""
                self.manager.screens[1].ln.text = ""
                self.manager.screens[1].mail.text = ""
                self.manager.screens[1].ph.text = ""
                self.manager.screens[1].error.text = ""
                self.ids.pas.text = ""
                self.ids.cpass.text = ""
                self.ids.otp.text = ""

            else:
                self.ids.error.text = "Password or Confirm Password should match"
        else:
            self.ids.error.text = "Wrong Password Enters :( "




    def on_text_password_wala(self):

        if not self.password_checking(self.ids.pas.text):
            self.ids.error.text = "Wrong Password Pattern"
        else:
            self.ids.error.text = ""

    def on_text_cpass_wala(self):

        if self.ids.cpass.text != self.ids.pas.text:
            self.ids.error.text = "Confirm password or password Should Match"

        else:

            self.ids.error.text = ""

    def password_checking(self,string):

        special_charcetrs = "!@#$%^&*?/~"
        num = "1234567890"
        chr = "abcdefghijklmnopqrstuvwxyz"
        x = False
        y = False
        z = False
        if len(string) >= 10:
            for i in special_charcetrs:
                if i in string:
                    x = True
                    break

            for i in special_charcetrs:
                if i in string:
                    y = True
                    break

            for i in chr:
                if i in string or i.upper() in string:
                    z = True
                    break

            if x and y and z:
                return True
            else:
                return False


        else:
            return False



    def otp_working(self):

        e_otp = self.ids.otp.text
        if len(e_otp) == 10:

            if e_otp == OTP:
                if otp_time_checker() :
                    self.ids.otp.disabled = True
                    self.ids.resend.disabled = True
                    self.ids.pas.disabled = False
                    self.ids.cpass.disabled = False
                    # self.ids.regis.disabled = False

                else:
                    self.ids.error.text = "Time Over ! Request For New OTP "
            else:
                self.ids.error.text = "INVALID OTP"
        else:
            self.ids.error.color = "red"
            self.ids.error.text = ""


    def Resending_otp(self):
        self.ids.otp.text = ""
        self.ids.otp.disabled = True
        thread = threading.Thread(target=self.otp_sender, args=(self.manager.screens[1].mail.text,))
        thread.start()
        self.ids.error.color = "green"
        self.ids.error.text = "Resending The Otp ...... "


    def otp_sender(self,mail):
        global otp_time
        Otp_maker()
        sub = "Otp for Sign UP in Data Encryptor/Decryptor "
        message = \
            f'''
    Otp For Sign UP : {OTP} 

    Otp is valid for only 60 sec 
    Please do not share the otp for the security purpose 

    Thanks  
            '''
        try:
            send_email(mail, sub, message)
            otp_time = datetime.datetime.now()
            self.ids.error.text = "OTp sent Succesfully"
            self.ids.otp.disabled = False
            return True
        except Exception as e:
            self.ids.error.color = "red"
            self.ids.error.text = "   Something went wrong :( \n Check Your Internet Connection "
            return False


    def Register_data(self):
        x = {'password': self.ids.pas.text,
             'phone': self.manager.screens[1].ph.text,
             'first name': self.manager.screens[1].fn.text,
             'last name': self.manager.screens[1].ln.text}
        id = self.manager.screens[1].mail.text

        data = ""
        try:
            file = open("user.txt", "r")
            data = file.read()
            file.close()
        except:
            pass

        if data == "":
            dict = {id: x}
        else:
            dict = json.loads(data)
            dict[id] = x

        with open("user.txt", "w") as file:
            file.write(json.dumps(dict))





class Register_screen(Screen):

    def Signup(self):
        x = [self.ids.fn.text, self.ids.ln.text, self.ids.ph.text, self.ids.mail.text]

        if '' not in x:
            if self.check_email():
                thread = threading.Thread(target=self.otp_sender,args=(self.ids.mail.text,))
                thread.start()
                self.ids.error.text = "Wait For A while ..... "
            else:
                self.ids.error.text = "Email Already Register With us .. Try to Login"
            # self.manager.current = "otp"
        else:
            self.ids.error.text = "Fill all Fields !!"

    def check_email(self):
        data = ""

        try:
            file = open("user.txt","r")
            data = file.read()
        except:
            pass

        if data == "":
            return True
        else:
            data = json.loads(data)
            if self.ids.mail.text in data:
                return False
        return True

    def otp_sender(self,mail):
        global otp_time
        Otp_maker()
        sub = "Otp for Sign UP in Data Encryptor/Decryptor "
        message = \
            f'''
    Otp For Sign UP : {OTP} 

    Otp is valid for only 60 sec 
    Please do not share the otp for the security purpose 

    Thanks  
            '''

        x = send_email(mail, sub, message)
            # otp_time = datetime.datetime.now()
        if x[0] == 1:
            Clock.schedule_once(self.update_ui, 0)
            self.ids.error.text = " "
            return True
        else:
            self.ids.error.text = "\tSomething went wrong :( \n Check Your Mail Id or Internet Connection "
            return False

    def update_ui(self,dt,*args):
        self.manager.current = "otp"

# ----------------------------------------------------------
# Decrytion Part


class Decryption(Screen):

    qr_path = None
    file_path = None

    def choosefile(self):
        self.ids.error.text = ""
        Tk().withdraw()
        try:
            Path = askopenfilenames(filetypes=[('Text Files', '*.txt')])
            self.file_path = Path[0]
        except:
            pass


    def select_qr(self):
        self.ids.error.text = ""
        Tk().withdraw()
        try:
            Path = askopenfilenames(filetypes=[('Image Files', '*.png')])
            self.qr_path = Path[0]
        except:
            pass

    def Decrypting(self):
        self.ids.choose.disabled = True
        self.ids.home.disabled = True
        self.ids.qr.disabled = True
        self.ids.decrypt.disabled = True
        self.ids.error.text = "Decrypting The file ..............."
        th = threading.Thread(target=self.decrypt_text())
        th.start()

    def Normal(self):
        self.ids.choose.disabled = False
        self.ids.home.disabled = False
        self.ids.qr.disabled = False
        self.ids.decrypt.disabled = False

    def decrypt_text(self):

        if self.file_path == None or self.file_path == "":
            self.ids.error.text = "Choose The file to be Decrypted :)"
            self.Normal()
        elif self.qr_path == None or self.qr_path == "":
            self.ids.error.text = "Choose the Qr Image Asoociate With the encrypted file"
            self.Normal()
        else:
            try:
                with open(self.file_path,"r") as file:
                    z = file.readlines()
                    a = ast.literal_eval(z[0])

                try:
                    dec = decode(Image.open(self.qr_path))
                    qr_data = dec[0].data.decode('ascii')
                    b = ast.literal_eval(qr_data)
                except:
                    self.ids.error.text = "Invalid Qr - Image provided "
                    self.Normal()
                    return

                try:
                    x = decrypt_message(a,b)
                    x = x.decode()
                    file = asksaveasfilename(initialfile='Untitled.txt', defaultextension=".txt",
                                           filetypes=[("All Files", "*.*"), ("Text Documents", "*.txt")])
                    with open(file,"w") as f:
                        f.write(x)
                    self.ids.error.text = "File Decrypted Successfully :)"
                    self.Normal()
                except Exception as e:
                    self.ids.error.text = "Wrong Qr or File Provided "
                    self.Normal()

            except Exception as e:
                self.ids.error.text = "Unable to decrypt File"
                self.Normal()

# ----------------------------------------------------------

# Encryption work ---------------------------------------------------------------------

class Encryption(Screen):
    cont = StringProperty('')
    path = None
    save_path = None
   
    def select_file(self):
        self.cont = " "
        Tk().withdraw()
        # self.manager.screens[4].error.text = ""
        try:
            Path = askopenfilenames(filetypes=[('All Files', '*.*')])
            self.path = Path[0]
        except:
            pass

    def encrpyt_file(self):
        self.cont = ''
        content = ''
        Tk().withdraw()
        try:

            try:
                self.save_path = asksaveasfilename(initialfile='Untitled.txt', defaultextension=".txt",
                                           filetypes=[("All Files", "*.*")])

                self.cont = "Encrypting File ..... Please WAIT FOR a while :)"
                self.ids.choose.disabled = True
                self.ids.encrypt.disabled = True
                self.ids.home.disabled = True

                th = threading.Thread(target=self.Encrypting)
                th.start()

            except Exception as e:
                self.cont = "File saving failure Encrypt Again :) "


        except:
            # self.manager.screens[4].error.text = "First Choose The file :( "
            self.cont = 'First Choose the File :( '

    def Encrypting(self):
        x = str(self.path)
        file = open(x,"r")
        content = file.read()
        encrypt = encrypt_message(content)
        maindata = encrypt[:3]
        Key = encrypt[3]
        decryptkey = Secret_key(Key)

        try:

            self.Qr_manage(decryptkey)

            with open(self.save_path,"w") as f:
                f.write(str(maindata))
                f.write("\n")
                f.write(str(encrypt[3]))

            self.ids.error.text = "File Encrypted Sucessfully  :) "
            self.ids.choose.disabled = False
            self.ids.home.disabled = False
            self.ids.encrypt.disabled = False

            return True

        except Exception as e:
            print(e)
            self.ids.error.text = "File Encryption Failure !!!!! "
            self.ids.choose.disabled = False
            self.ids.home.disabled = False
            self.ids.encrypt.disabled = False

            return False


    def Qr_manage(self,x):
        x = qrcode.make(str(x))
        x.save("qr_img.png")

        # mail = "dipanshuaggarwal17@gmail.com"
        subject = "Qr code for the encrypted file :)"
        msg = '''This is the Qr associate for Your Currently Encrypted file

        Don't share this QR code with anyone For security Purpose

        Thanks
        '''

        photo = "qr_img.png"
        x = send_email(Email,subject,msg,True,photo)
        os.remove("qr_img.png")
        if x[0] == 1:
            return
        else:
            self.ids.error.text = "Check Your Internet Connection :) "
        raise Exception("Internet connection Problem")


# -------------------------------------------------------------------------------------------------------------------------------------------------


# Main App functionality :)
class My_app(App):
    def build(self):
        return Builder.load_file('app.kv')


if __name__ == '__main__':
    My_app().run()
