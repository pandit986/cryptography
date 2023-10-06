# Create your views here.
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from Project_GPA.settings import N, TBA, EMAIL_HOST_USER, ALLOWED_HOSTS
from .models import LoginInfo, msgInfo
import random, uuid

cover_text = "Decision Support Systems As the name implies, decision support " \
             "systems are designed to empower " \
             "the user with the ability to make effective decisions regarding " \
             "both the current and future state of an organization. " \
             "To do so, the DSS(decision support system)"
class Stego:
    def __init__(self, message):
        self.message = message

    def get_Bin(self, message):
        bin_message = ""
        for c in message:
            if 64 < ord(c) < 91:
                dec = ord(c) % 64
                bin_message = bin_message+"".join(format(dec, '05b'))
            elif 96 < ord(c) < 123:
                dec = ord(c) % 32
                bin_message = bin_message+"".join(format(dec, '05b'))
            if ord(c) == 32:
                bin_message = bin_message+"".join(format(0, '05b'))
            if ord(c) == 46:
                bin_message = bin_message+"".join(format(27, '05b'))
            if ord(c) == 40:
                bin_message = bin_message + "".join(format(28, '05b'))
            if ord(c) == 41:
                bin_message = bin_message + "".join(format(29, '05b'))
            if ord(c) == 44:
                bin_message = bin_message + "".join(format(30, '05b'))
            if ord(c) == 64:
                bin_message = bin_message + "".join(format(31, '05b'))

        return bin_message

    def create_Stego(self, msg, cover):
        cipher_text = "1" + "".join(format(len(self.message), '08b'))
        i = 0
        while i < len(self.message)*5 + 1:
            #print(msg[i:i+5])
            cipher_text = cipher_text + "".join(msg[i:i+5]) + "".join(cover[i:i+5])
            i += 5
        cipher_text = cipher_text + "".join(cover[i:1275])
        no_of_extra_bits = 7 - len(cipher_text) % 7
        cipher_text = cipher_text + "".join("1"*no_of_extra_bits)
        return cipher_text

    def get_Stego(self):
        imp_text_bin = self.get_Bin(self.message)
        #print("5 Bit Binary representation of Original Message\n",imp_text_bin)
        #print("5 Bit Binary Representation of Cover Text")
        cover_text_bin = self.get_Bin(cover_text)
        #print(cover_text_bin)
        return self.create_Stego(imp_text_bin, cover_text_bin)

def stego_string_equivalent(stego_text):
        sev_bit_eq_msg = ""
        i = 0
        while i < len(stego_text):
            sev_bit_eq_msg += "".join(chr(int(stego_text[i:i + 7], 2)))
            i += 7
        return sev_bit_eq_msg

def sev_bit_equivalent(stego_text):
        sev_bit_eq = ""
        i = 0
        print(len(stego_text))
        while i < len(stego_text):
            sev_bit_eq += "".join(format(ord(stego_text[i]), '07b'))
            i += 1
        return sev_bit_eq

def stego_decrypt(stego_msg):
        stego_bin = "".join(format(stego_msg, '02b'))
        print(stego_bin)
        origin_msg_length = int(stego_bin[1:9],2)
        removed_flag_bin = stego_bin[9:]  # string after removal of first 9 bits
        i = 0
        original_message = ""
        while i < origin_msg_length:
            dec = int(removed_flag_bin[i * 10:i * 10 + 5], 2)
            if dec == 0:
                original_message += "".join(" ")
            elif 0 < dec < 27:
                original_message += "".join(chr(96 + dec))
            elif dec == 27:
                original_message += "".join(format(chr(46)))
            elif dec == 28:
                original_message += "".join(format(chr(40)))
            elif dec == 29:
                original_message += "".join(format(chr(41)))
            elif dec == 30:
                original_message += "".join(format(chr(44)))
            else:
                original_message += "".join(format(chr(64)))

            i += 1

        print(original_message)
        return original_message

def toInt(message_string):
    message = int(message_string,2)
    return message

def toInt10(message_string):
    message = int(message_string)
    return message



class RSA:
    def __init__(self):
        self.e = self.d = self.p = self.q = self.phi = self.n = 0

    def __egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.__egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def __modinv(self, a, m):
        g, x, y = self.__egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m

    def encrypt(self, m, keyPair=None):
        if (keyPair == None):
            keyPair[0] = self.e
            keyPair[1] = self.n

        return pow(m, keyPair[0], keyPair[1])

    def decrypt(self, c, keyPair=None):
        if (keyPair == None):
            keyPair[0] = self.d
            keyPair[1] = self.n

        return pow(c, keyPair[0], keyPair[1])

    def generateKeys(self, e=65537):
        self.p = 104167339441343052334143655346881025579355991825465206329717530939449308713769159720734604878896568014513644604557936485703969764100585253718493352603026802223900294478820395948769898675120364410093977580637743697509839740967230428101232267682780681996889088689281143787187967464341421457259289037286852891567
        self.q = 95166900491413432309552208283266025276058896541161844022785678332630297697960237648176053174895260452133630928283251702325863173453262998632531327184152478429661209032767107376225412444761648231372173868834877903710252675294579569689943118954629326283159391160654665405971624055491910397359298597464013642213

        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = e
        self.d = self.__modinv(self.e, self.phi)
        
        if (self.phi % self.e == 0):
            raise Exception('invalid values for p and q')

    def getMaxMessageBits(self):
        return self.n.bit_length()

    def getPublicKey(self):
        return self.e, self.n

    def getPrivateKey(self):
        return self.d, self.n

def get_pwd_imgs():
    # These images are just to confuse the attacker
    p_images = []
    i = 1
    while i<37:
        temp = []
        for j in range(i,i+6):
            temp.append(j)
        p_images.append(temp)
        i += 6
    print(p_images)
    return p_images


def update_login_info(user, didSuccess):
    if didSuccess:
        user.logininfo.fails = 0
    else:
        user.logininfo.fails += 1

    user.logininfo.save()
    print('{} Failed attempts: {}'.format(user.username, user.logininfo.fails))


def isBlocked(username):
    try:
        user = User.objects.get(username=username)
    except Exception:
        return None
    print('isBlocked: {} - {}'.format(user.logininfo, TBA))
    if user.logininfo.fails >= TBA:
        return True
    else:
        return False


def sendLoginLinkMailToUser(username):
    user = User.objects.get(username=username)
    # send email only id user.logininfo.login_link is not None
    if user.logininfo.login_link is None:
        link = str(uuid.uuid4())
        user.logininfo.login_link = link
        user.logininfo.save()
        email = EmailMessage(
            subject='Link to Log in to your account',
            body='''
            Someone tried to bruteforce on your account.
            Click the Link to Login to your account directly.
            The link is one-time clickable
            link: http://{}:8000/login/{}
            '''.format(ALLOWED_HOSTS[-1], link),  # might wanna change the allowd_host
            from_email=EMAIL_HOST_USER,
            to=[user.email],
        )
        email.send()
        print('LOGIN LINK EMAIL SENT')


def sendPasswordResetLinkToUser(username):
    # send reset link everytime user requests
    try:
        user = User.objects.get(username=username)
    except Exception:
        return False

    link = str(uuid.uuid4())
    user.logininfo.reset_link = link
    user.logininfo.save()
    email = EmailMessage(
        subject='Link to Rest your Password',
        body='''
        You have requested to reset your password.
        Click the Link to reset your password directly.
        The link is one-time clickable
        link: http://{}:8000/reset/{}
        '''.format(ALLOWED_HOSTS[-1], link),  # might wanna change the allowd_host
        from_email=EMAIL_HOST_USER,
        to=[user.email],
    )
    email.send()
    print('PWD RESET LINK EMAIL SENT')
    return True


def home_page(request):
    return render(request, 'home.html')


def register_page(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        print(username, password)
        try:
            # create user and loginInfo for him
            if len(password)>5:
                user = User.objects.create_user(email=email, username=username, password=password)
                login_info = LoginInfo(user=user, fails=0)
                login_info.save()
                messages.success(request, 'Account created successfully!')
            else:
                messages.warning(request,'Select Atleast 5 images')
        except Exception:
            messages.warning(request, 'Error while creating Account!')

        return redirect('home')
    else:
        data = {
            'p_images': get_pwd_imgs(),
        }
        return render(request, 'register.html', context=data)


def login_page(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(username, password)

        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            return redirect('login')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            return redirect('login')
        else:
            # Not Blocked
            user = authenticate(username=username, password=password, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                messages.success(request, 'Login successfull!')
                return redirect('dashboard')
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                return redirect('login')

    else:
        data = {
            'p_images': get_pwd_imgs(),
        }
        return render(request, 'login.html', context=data)


def login_from_uid(request, uid):
    try:
        # get user from the uid and reset the Link to 'NO_LINK' again
        login_info = LoginInfo.objects.get(login_link=uid)
        user = login_info.user
        login(request, user)
        update_login_info(user, True)
        login_info.login_link = None
        login_info.save()
        messages.success(request, 'Login successfull!')
    except Exception:
        messages.warning(request, 'Invalid Link. Please check again!')

    return redirect('home')


def reset_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        print(username)
        if sendPasswordResetLinkToUser(username):
            messages.success(request, 'Password Reset Link sent to you email!')
        else:
            messages.warning(request, 'User doesn\'t exist!')
        return redirect('home')
    else:
        return render(request, 'reset_request.html')


def reset_from_uid(request, uid):
    print('hello')
    if request.method == 'POST':
        print('hi-post')
        password = request.POST['password']
        try:
            # get user from the uid and reset the Link to 'NO_LINK' again
            login_info = LoginInfo.objects.get(reset_link=uid)
            user = login_info.user
            # reset pwd
            user.set_password(password)
            login_info.reset_link = None
            login_info.save()
            user.save()
            messages.success(request, 'Password Changed Successfully!')
        except Exception:
            messages.warning(request, 'Invalid Link. Please check again!')
        return redirect('home')
    else:
        print('hi-else')
        try:
            # To make sure the link is valid
            print(uid)
            login_info = LoginInfo.objects.get(reset_link=uid)
            data = {
                'p_images': get_pwd_imgs(),
            }
            return render(request, 'reset.html', context=data)
        except Exception:
            messages.warning(request, 'Invalid Link. Please check again!')
            return redirect('home')


def logout_page(request):
    logout(request)
    messages.warning(request, 'You\'ve been logged out!')
    return redirect('home')

def error_page(request):
    return render(request,'error.html')

def send_msg(request):
    if request.method == 'POST':
            sender = request.user.username
            receiver = request.POST['receiver']
            msg = request.POST['msg']
            stego = Stego(msg)
            stego_text_bin= stego.get_Stego()

            print("Stego Text Binary:\n",stego_text_bin)
            msg = stego_string_equivalent(stego_text_bin)

            print("\n7-Bit Equivalent of stego Text\n",msg)
            stego_msg_to_int = toInt(stego_text_bin)
            rsa = RSA()
            rsa.generateKeys()
            encrypted = rsa.encrypt(stego_msg_to_int, keyPair=rsa.getPrivateKey())
            print("Encrypted Text By RSA\n",encrypted)
            MSG_Object = msgInfo(sender=sender, receiver=receiver, msg=encrypted)
            MSG_Object.save()
            return redirect('send_msg')
    else:
        list_of_users = User.objects.only('username')
        temp_list = []
        for user in list_of_users:
            temp_list.append(user.username)
        data = {'users' : temp_list}
        return render(request, 'send_msg.html',context=data)

def receive_msg(request):
    options_list = ["all", "last 1", "last 5","last 10"]
    data = {'options':options_list}
    if request.method == 'POST':
        username = request.user.username
        received_messages = msgInfo.objects.filter(receiver=username)
        rsa = RSA()
        rsa.generateKeys()
        if len(received_messages):
            if request.POST['no_of_msg'] == ("last 1" or "last 5" or "last 10"):
                asked_msg_no = int(request.POST['no_of_msg'].split()[1])
                data['msg'] = received_messages[:asked_msg_no]
                msg_list = []
                for msges in data['msg']:
                    msgess = toInt10(msges.msg)
                    decrypted = rsa.decrypt(msgess, keyPair=rsa.getPublicKey())
                    print("\nMessage Decrypted by RSA")
                    print(decrypted)
                    msg_list.append(stego_decrypt(decrypted))
                sender_list = []
                for sen in data['msg']:
                    sender_list.append(sen.sender)
                print(sender_list)
                data['msg'] = zip(sender_list,msg_list)
            else:
                data['msg'] = received_messages
                msg_list = []
                for msges in data['msg']:
                    msgess = toInt10(msges.msg)
                    print(type(msgess))
                    decrypted = rsa.decrypt(msgess, keyPair=rsa.getPublicKey())
                    print("\nMessage Decrypted by RSA")
                    print(decrypted)
                    msg_list.append(stego_decrypt(decrypted))
                sender_list = []
                for sen in data['msg']:
                    sender_list.append(sen.sender)
                data['msg'] = zip(sender_list, msg_list)
                print(data['msg'])
            return render(request,'receive_msg.html',context=data)
        else:
            return render(request,'receive_msg.html',context=data)
    else:
        return render(request,'receive_msg.html', context=data)

def dashboard_page(request):
    return render(request,'dashboard.html')
