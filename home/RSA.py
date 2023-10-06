

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
        print(self.d)
        if (self.phi % self.e == 0):
            raise Exception('invalid values for p and q')

    def getMaxMessageBits(self):
        return self.n.bit_length()

    def getPublicKey(self):
        return self.e, self.n

    def getPrivateKey(self):
        return self.d, self.n





def toInt(message_string):
    message = int(message_string, 2)
    return message


def rsa_operation(message_bstring):
    stego_msg_to_int = toInt(message_bstring)
    rsa = RSA()
    rsa.generateKeys()
    encrypted = rsa.encrypt(stego_msg_to_int, keyPair=rsa.getPrivateKey())
    print("Message Decimal String\n",stego_msg_to_int)
    print("Cipher Text By RSA\n", encrypted)
    decrypted = rsa.decrypt(encrypted, keyPair=rsa.getPublicKey())
    print("\nMessage Decrypted by RSA")
    print(decrypted)
    return decrypted
rsa = RSA()
rsa.generateKeys()


