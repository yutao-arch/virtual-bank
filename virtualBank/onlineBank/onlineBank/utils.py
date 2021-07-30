import base64
import hashlib
import json
import random
import urllib
from random import Random
from urllib import parse, parse, request

import Crypto
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Util.Padding import pad, unpad
from authenticate.models import Account, User
from usersModule.models import Bills
from Crypto.Hash import SHA, SHA256
from base64 import b64decode, b64encode

from .config import Config


def rsa_decrypt(ciphers):
    # rsa解密
    plaintext = []
    private_key = RSA.import_key(
        open(Config.key_url + "RSA_private.pem",
             "rb").read(),
    )
    cipher_rsa = PKCS1_cipher.new(private_key)
    for cipher in ciphers:
        data = parse.unquote(cipher)  # 转化成字典形式
        data = base64.b64decode(data)  # 解码
        data = cipher_rsa.decrypt(data, None)
        try:
            plaintext.append(data.decode())
        except (AttributeError, UnicodeDecodeError):
            return data
    return plaintext


def aes_decrypt(ciphers, key):
    plaintext = []
    for cipher in ciphers:
        aes = AES.new(key, AES.MODE_CBC, key)
        cipher = base64.urlsafe_b64decode(parse.unquote(cipher))
        cipher = unpad(aes.decrypt(cipher), AES.block_size)
        try:
            plaintext.append(cipher.decode())
        except UnicodeDecodeError:
            plaintext.append(cipher)
    return plaintext


def aes_encrypt(plaintext, key):
    plaintext = plaintext.encode()
    key = AES.new(key, AES.MODE_CBC, key)
    ct_bytes = key.encrypt(pad(plaintext, AES.block_size))
    ct = base64.b64encode(ct_bytes)
    ct = ct.decode('utf-8')
    return ct


def md5(text):
    if type(text) == str:
        text = text.encode()
    return hashlib.md5(text).hexdigest()


def get_rsa_pubkey():
    pub_key = open(
        Config.key_url + "RSA_public.pem",
        "rb").read().decode()
    return pub_key


def get_salt(length=4):
    # 生成随机盐值
    salt = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    len_chars = len(chars) - 1
    random = Random()
    for i in range(length):
        salt += chars[random.randint(0, len_chars)]
    return salt


def set_salt(request, name=None):
    salt = get_salt(Config.salt_Length)
    if not name:  # 如果参数没有name，就随机生成一个salt_id和其对应的随机盐值salt存储在session中
        salt_id = random.randint(0, Config.max_saltId)
        request.session[salt_id] = salt
    else:  # 如果有参数name，则为其session的name对应的['salt']赋予随机生成的盐值salt
        tmp = request.session[name]
        tmp['salt'] = salt
        request.session[name] = tmp
        return salt
    return [salt_id, salt]


def get_account_by_card(card):
    user = User.objects.get(card=card)
    account = Account.objects.get(user=user.phone)
    return account


def get_user_by_card(card):
    user = User.objects.get(card=card)
    return user


def sha256(texts):
    sha = hashlib.sha256()
    for tex in texts:
        if type(tex) == str:
            tex = tex.encode()
        sha.update(tex)
    return sha.hexdigest()


def if_login(request, name):
    # 判断用户是否登录
    user = request.session.get(name, None)
    if not (user and user.get('is_login', None)):
        return False
    return True


def sha_pre(ciphers):
    # 解析信息
    after = []
    for item in ciphers:
        data = parse.unquote(item)  # 把"item=b"解析为"item":"b"的字典形式
        after.append(data)
    b = (''.join(after))
    b = b.encode()
    return b


def verify_sign(ciphers, signature, name):
    # 验证签名
    data = sha_pre(ciphers)
    h = Crypto.Hash.SHA256.new()
    h.update(data)
    user = User.objects.get(name=name)
    pub_key = user.pub_key  # 直接读取数据库该用户的公钥的路径
    if not pub_key:  # 如果数据库中没有该公钥，(该功能不实现：默认银行管理员储存了所有用户的公钥，则向CA请求该用户的公钥)
        return False
        # pub_key = get_userpub(name)
        # if not pub_key:
        #     return False
    user_pubkey = RSA.import_key(open(pub_key, "r").read())
    signature = base64.b64decode(sha_pre(signature))
    return PKCS1_signature.new(user_pubkey).verify(h, signature)


def get_user(name):
    user = User.objects.get(name=name)
    return user


def get_account(name):
    user = get_user(name)
    return Account.objects.get(user=user.phone)


def get_userby_phone(phone):
    return User.objects.get(phone=phone)


def creat_bill(name, bene_card, amount, bill_type):
    # 在数据库中创建账单
    try:
        user = get_user(name)
        if bill_type == "recharge":
            Bills.objects.create(payer=name, payer_card=name, beneficiary=user.card, amount=amount,
                                 bill_type=bill_type)
        elif bill_type == "withdraw":
            Bills.objects.create(payer=name, payer_card=user.card, beneficiary=name, amount=amount,
                                 bill_type=bill_type)
        else:
            Bills.objects.create(payer=name, payer_card=user.card, beneficiary=bene_card, amount=amount,
                                 bill_type=bill_type)
        return True
    except Exception as e:
        print(e)
        return False


def verify_certsign(ciphers, signature):
    # 对证书进行认证
    data = sha_pre(ciphers)
    signature = sha_pre([signature])
    sha = Crypto.Hash.SHA256.new()
    sha.update(data)
    path = get_user("CA").pub_key  # 得到CA公钥的路径
    pub = open(path, "r").read()   # 读取该公钥
    pubkey = RSA.import_key(pub)  # 导入该公钥
    signature = base64.b64decode(signature)
    return PKCS1_signature.new(pubkey).verify(sha, signature)


def part_cert(cert):
    # 得到证书中除了签名的其他信息
    infos = []
    for i in ['version', 'publickey', 'cert_seq', 'DN', 'validData', 'ca']:  # 数字证书中部分字段。用来验证
        infos.append(cert[i])
    return infos


def part_and_verify(cert):
    # 验证证书
    # 参数中cert为证书
    if type(cert) == str:
        cert = json.loads(cert)  # 将cert转化为字典
    infos = part_cert(cert)  # 得到证书中的部分信息
    return verify_certsign(infos, cert['signature'])


def post(url, post_data):
    # 一个简化版的封装的post命令
    headers = {
        'User-Agent': Config.User_Agent}
    post_data = urllib.parse.urlencode(post_data).encode()
    req = request.Request(url=url, data=post_data, headers=headers)
    data = request.urlopen(req).read().decode()
    return data


# 现在默认银行提前下好了所有用户的证书并进行了验证，存储了所有用户的公钥
# def get_userpub(name):
#     # 向CA认证中心请求得到自身的公钥
#     post_data = {
#         "User": name
#     }
#     ca_url = Config.CA_GetCert
#     data = post(ca_url, post_data)  # 向CA请求得到数据
#     certinfo = json.loads(data)['certInfo']  # 从数据中中取出证书certInfo的内容
#     if part_and_verify(certinfo):
#         with open(
#                 Config.key_url + name + "_pub.pem",
#                 "w+") as f:
#             f.write(certinfo['publickey'])  # 创建文件从证书中得到公钥，并将用户公钥写入文件
#         user = get_user(name)
#         user.pub_key = Config.key_url + name + "_pub.pem"  # 写入数据库中的路径文件
#         user.save()
#         return user.pub_key
#     else:
#         return False


############################################## 以下为为了和商城交互而修改的新版各种加密解密算法，urlsafe版
def verify_sign_yt(ciphers, signature, name):  # 还需要加入name参数
    # 验证签名
    user = User.objects.get(name=name)
    pub_key = user.pub_key  # 直接读取数据库该用户的公钥的路径
    if not pub_key:  # 如果数据库中没有该公钥，(该功能不实现：默认银行管理员储存了所有用户的公钥，则向CA请求该用户的公钥)
        return False
        # pub_key = get_userpub(name)
        # if not pub_key:
        #     return False
    key = RSA.import_key(
        open(Config.key_url + name + "_public.pem",
             "rb").read(),
    )
    hash_value = SHA256.new(bytes(ciphers, encoding="utf-8"))
    verifier = PKCS1_signature.new(key)
    if verifier.verify(hash_value, base64.urlsafe_b64decode(signature)):
        return True
    else:
        return False


def create_sign_yt(ciphers):  # 还不能对多参数进行生成签名
    # 生成银行的签名
    key = RSA.import_key(
        open(Config.key_url + "RSA_private.pem",
             "rb").read(),
    )
    hash_value = SHA256.new(bytes(ciphers, encoding="utf-8"))
    signer = PKCS1_signature.new(key)
    signature = signer.sign(hash_value)
    return base64.urlsafe_b64encode(signature).decode('utf-8')


def create_key(name):
    # 生成公钥和私钥
    key = RSA.generate(1024)
    encrypted_key = key.exportKey(pkcs=8, protection="scryptAndAES128-CBC")
    with open(
            Config.key_url + name +"_private.pem",
            "wb+") as f:
        f.write(encrypted_key)
    with open(
            Config.key_url + name+"_public.pem",
            "wb+") as f:
        f.write(key.publickey().exportKey())


def rsa_encrypt_yt(msg, name):  # RSA加密
    public_key = RSA.import_key(
        open(Config.key_url + name +"_public.pem",
             "rb").read(),
    )
    cipher = PKCS1_cipher.new(public_key)
    encrypt_text = base64.urlsafe_b64encode(cipher.encrypt(bytes(msg.encode("utf8"))))
    return encrypt_text.decode('utf-8')


def rsa_decrypt_yt(ciphers):
    # rsa解密
    plaintext = []
    private_key = RSA.import_key(
        open(Config.key_url + "RSA_private.pem",
             "rb").read(),
    )
    cipher_rsa = PKCS1_cipher.new(private_key)
    for cipher in ciphers:
        data = parse.unquote(cipher)  # 转化成字典形式
        data = base64.urlsafe_b64decode(data)  # 解码
        data = cipher_rsa.decrypt(data, None)
        try:
            plaintext.append(data.decode())
        except (AttributeError, UnicodeDecodeError):
            return data
    return plaintext

