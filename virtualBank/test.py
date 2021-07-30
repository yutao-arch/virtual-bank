import hashlib
import json
import os
import urllib
from _sha256 import sha256
from urllib import parse, request
from base64 import b64decode

from Crypto.Cipher import AES
from Crypto.Hash import SHA, SHA256
from base64 import b64decode, b64encode
import base64
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher



# 所有的测试代码
#########################################################################
# 生成公钥和私钥


# def create_key(name):
#     key = RSA.generate(1024)
#     encrypted_key = key.exportKey(pkcs=8, protection="scryptAndAES128-CBC")
#     with open(
#             name +"_private.pem",
#             "wb+") as f:
#         f.write(encrypted_key)
#     with open(
#             name+"_public.pem",
#             "wb+") as f:
#         f.write(key.publickey().exportKey())
#
#
# def rsa_encrypt(msg):  # RSA加密
#     public_key = RSA.import_key(
#         open("RSA_public.pem",
#              "rb").read(),
#     )
#     cipher = PKCS1_cipher.new(public_key)
#     encrypt_text = base64.b64encode(cipher.encrypt(bytes(msg.encode("utf8"))))
#     return encrypt_text.decode('utf-8')
#
#
# def rsa_decrypt(ciphers):
#     # rsa解密
#     plaintext = []
#     private_key = RSA.import_key(
#         open("RSA_private.pem",
#              "rb").read(),
#     )
#     cipher_rsa = PKCS1_cipher.new(private_key)
#     for cipher in ciphers:
#         data = parse.unquote(cipher)  # 转化成字典形式
#         data = base64.b64decode(data)  # 解码
#         data = cipher_rsa.decrypt(data, None)
#         try:
#             plaintext.append(data.decode())
#         except (AttributeError, UnicodeDecodeError):
#             return data
#     return plaintext
#
#
#
# def aes_encrypt(plaintext, key):
#     plaintext = plaintext.encode()
#     key = AES.new(key, AES.MODE_CBC, key)
#     ct_bytes = key.encrypt(pad(plaintext, AES.block_size))
#     ct = base64.b64encode(ct_bytes)
#     ct = ct.decode('utf-8')
#     return ct
#
#
# def aes_decrypt(ciphers, key):
#     plaintext = []
#     for cipher in ciphers:
#         aes = AES.new(key, AES.MODE_CBC, key)
#         cipher = base64.b64decode(parse.unquote(cipher))
#         cipher = unpad(aes.decrypt(cipher), AES.block_size)
#         try:
#             plaintext.append(cipher.decode())
#         except UnicodeDecodeError:
#             plaintext.append(cipher)
#     return plaintext
#
#
# def sha_pre(ciphers):
#     # 解析信息
#     after = []
#     for item in ciphers:
#         data = parse.unquote(item)  # 把"item=b"解析为"item":"b"的字典形式
#         after.append(data)
#     b = (''.join(after))
#     b = b.encode()
#     return b


# def verify_sign_yt(ciphers, signature):  # 需要加路径参数，还没有实现对多参数的确认
#     #  # 验证签名
#     # user = User.objects.get(name=name)
#     # pub_key = user.pub_key  # 直接读取数据库该用户的公钥的路径
#     # if not pub_key:  # 如果数据库中没有该公钥，则向CA请求该用户的公钥
#     #     pub_key = get_userpub(name)
#     #     if not pub_key:
#     #         return False
#     key = RSA.import_key(
#         open("CA_public.pem",
#              "rb").read(),
#     )
#     hash_value = SHA256.new(bytes(ciphers, encoding="utf-8"))
#     verifier = PKCS1_signature.new(key)
#     if verifier.verify(hash_value, b64decode(signature)):
#         return True
#     else:
#         return False


# def create_sign_yt(ciphers):  # 还不能对多参数进行生成签名
#     key = RSA.import_key(
#         open("CA_private.pem",
#              "rb").read(),
#     )
#     hash_value = SHA256.new(bytes(ciphers, encoding="utf-8"))
#     signer = PKCS1_signature.new(key)
#     signature = signer.sign(hash_value)
#     return b64encode(signature)


# def sign(data):
#     public_key = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJ4VKVjLT5w73AkKQZhgmoIXCEUNtoc8NwcQbXsrPInGkYhkUtE7KxGGwNncm4Cq+Zofc2nmZ3pWlT/LCd+jPfU8tTUuU69CVrpyqg9NcC3NU2zKlbZvbmEAS7+Cf9955xoi3yX8ozezbm8z1VFp5IACMZIDghQQAcNEEgANGblwIDAQAB'
#     private_key = 'MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMnhUpWMtPnDvcCQpBmGCaghcIRQ22hzw3BxBteys8icaRiGRS0TsrEYbA2dybgKr5mh9zaeZnelaVP8sJ36M99Ty1NS5Tr0JWunKqD01wLc1TbMqVtm9uYQBLv4J/33nnGiLfJfyjN7NubzPVUWnkgAIxkgOCFBABw0QSAA0ZuXAgMBAAECgYABPNnb5gDQHNkL6VaLctA75437rwXs2hOUGZga8ZQWKGHty8PAXsvRchWzgeFqqStfykYKsJ9PIe8/dZkihNl8tl+3u4aE/Tle/uz5Wtl0pd5iGkaJFgBkpyJ/AY6MyYHbKD6GAp2TBBnK5GuIv1x3Gsq4qZpij3xp25tOAdZQqQJBAN6FT0AfhUYfpFz+yEvAF9AhLp8vwHvCDgnJ3i4AsiYIIw0R4LNl7y5/Qc7ANWqNxAL3zSaPM8xg3kvWq+p8TLkCQQDoQQNamjxEgOskvqrFSfaeagq4VTheSMD2pe1doaiXeMmqIbx0Xth3rxTszCUNyQFAXRnFKTHsdCIrH0E7lyLPAkAPfHWcf9UVoUQeGLk11GOT34tQFtGtiz7Q3ZSx3OiJDw3pbfIWaiSwNrkMu4G8LauTjU1gvpybP66Y1pLWWdo5AkBDD3qTb5NVSFAdBPy0CH4wEXhU7y5ecu1cil52OZY/Xj4EZMdQZo5kSGZnVS6hw1ccKYWmWxWyK3ouL1EbjrEbAkASX6Sk6NMbkvUdOuoJhqaAjjFXcBQ6JaCcV/J4cO3u2PLcrEnufcMc9cr2b+q4R8u05IJsElGXs1xcpI2K0DCh'
#
#     key_bytes = bytes(private_key, encoding="utf-8")
#     key_bytes = b64decode(key_bytes)
#     key = RSA.importKey(key_bytes)
#     hash_value = SHA256.new(bytes(data, encoding="utf-8"))
#     signer = PKCS1_signature.new(key)
#     signature = signer.sign(hash_value)
#     return b64encode(signature)
#
#
# def verify(data, signature):
#     public_key = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJ4VKVjLT5w73AkKQZhgmoIXCEUNtoc8NwcQbXsrPInGkYhkUtE7KxGGwNncm4Cq+Zofc2nmZ3pWlT/LCd+jPfU8tTUuU69CVrpyqg9NcC3NU2zKlbZvbmEAS7+Cf9955xoi3yX8ozezbm8z1VFp5IACMZIDghQQAcNEEgANGblwIDAQAB'
#     private_key = 'MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMnhUpWMtPnDvcCQpBmGCaghcIRQ22hzw3BxBteys8icaRiGRS0TsrEYbA2dybgKr5mh9zaeZnelaVP8sJ36M99Ty1NS5Tr0JWunKqD01wLc1TbMqVtm9uYQBLv4J/33nnGiLfJfyjN7NubzPVUWnkgAIxkgOCFBABw0QSAA0ZuXAgMBAAECgYABPNnb5gDQHNkL6VaLctA75437rwXs2hOUGZga8ZQWKGHty8PAXsvRchWzgeFqqStfykYKsJ9PIe8/dZkihNl8tl+3u4aE/Tle/uz5Wtl0pd5iGkaJFgBkpyJ/AY6MyYHbKD6GAp2TBBnK5GuIv1x3Gsq4qZpij3xp25tOAdZQqQJBAN6FT0AfhUYfpFz+yEvAF9AhLp8vwHvCDgnJ3i4AsiYIIw0R4LNl7y5/Qc7ANWqNxAL3zSaPM8xg3kvWq+p8TLkCQQDoQQNamjxEgOskvqrFSfaeagq4VTheSMD2pe1doaiXeMmqIbx0Xth3rxTszCUNyQFAXRnFKTHsdCIrH0E7lyLPAkAPfHWcf9UVoUQeGLk11GOT34tQFtGtiz7Q3ZSx3OiJDw3pbfIWaiSwNrkMu4G8LauTjU1gvpybP66Y1pLWWdo5AkBDD3qTb5NVSFAdBPy0CH4wEXhU7y5ecu1cil52OZY/Xj4EZMdQZo5kSGZnVS6hw1ccKYWmWxWyK3ouL1EbjrEbAkASX6Sk6NMbkvUdOuoJhqaAjjFXcBQ6JaCcV/J4cO3u2PLcrEnufcMc9cr2b+q4R8u05IJsElGXs1xcpI2K0DCh'
#
#     key_bytes = bytes(public_key, encoding="utf-8")
#     key_bytes = b64decode(key_bytes)
#     key = RSA.importKey(key_bytes)
#     hash_value = SHA256.new(bytes(data, encoding="utf-8"))
#     verifier = PKCS1_signature.new(key)
#     if verifier.verify(hash_value, b64decode(signature)):
#         print("The signature is authentic.")
#     else:
#         print("The signature is not authentic.")

# # url_safe版rsa解密
# def rsa_decrypt_yt(ciphers):
#     # rsa解密
#     plaintext = []
#     private_key = RSA.import_key(
#         open("RSA_private.pem",
#              "rb").read(),
#     )
#     cipher_rsa = PKCS1_cipher.new(private_key)
#     for cipher in ciphers:
#         data = parse.unquote(cipher)  # 转化成字典形式
#         data = base64.urlsafe_b64decode(data)  # 解码
#         data = cipher_rsa.decrypt(data, None)
#         try:
#             plaintext.append(data.decode())
#         except (AttributeError, UnicodeDecodeError):
#             return data
#     return plaintext
#
# def md5(text):
#     if type(text) == str:
#         text = text.encode()
#     return hashlib.md5(text).hexdigest()
#
#
#
# # url_safe版验签名
def verify_sign_yt(ciphers, signature, name):
    # 验证签名
    # user = User.objects.get(name=name)
    # pub_key = user.pub_key  # 直接读取数据库该用户的公钥的路径
    # if not pub_key:  # 如果数据库中没有该公钥，则向CA请求该用户的公钥
    #     pub_key = get_userpub(name)
    #     if not pub_key:
    #         return False
    key_url = "C:\\Users\\yutao\\PycharmProjects\\virtualBank\\onlineBank\\authenticate\\rsa\\"
    key = RSA.import_key(
        open(key_url + name + "_public.pem",
             "rb").read(),
    )
    hash_value = SHA256.new(bytes(ciphers, encoding="utf-8"))
    verifier = PKCS1_signature.new(key)
    if verifier.verify(hash_value, base64.urlsafe_b64decode(signature)):
        return True
    else:
        return False
#
#
# def verify_certsign(ciphers, signature):
#     # 对证书进行认证
#     data = sha_pre(ciphers)
#     signature = sha_pre([signature])
#     sha = Crypto.Hash.SHA256.new()
#     sha.update(data)
#     pub = RSA.import_key(
#         open("CA_public.pem",
#              "rb").read(),
#     )
#     pubkey = RSA.import_key(pub)  # 导入该公钥
#     signature = base64.b64decode(signature)
#     return PKCS1_signature.new(pubkey).verify(sha, signature)
#
#
# def part_cert(cert):
#     # 得到证书中除了签名的其他信息
#     infos = []
#     for i in ['Public Key']:  # 数字证书中部分字段。用来验证
#         infos.append(cert[i])
#     return infos
#
# def part_and_verify(cert):
#     # 验证证书
#     # 参数中cert为证书
#     if type(cert) == str:
#         cert = json.loads(cert)  # 将cert转化为字典
#     infos = part_cert(cert)  # 得到证书中的部分信息
#     return verify_certsign(infos, cert['Digital Signature'])

# 测试生成公钥和私钥
# create_key("WN")

# # 测试签名
# msg = 'message = aa'
#
# signature = create_sign_yt(msg)
# print(signature)
# # verify(msg, signature)
# # signature = create_sign_yt(msg)
# # print(signature)
# if verify_sign_yt(msg, signature, "CA"):
#     print("验证成功")

# # 测试字符串转化
# data={"name":"王尼玛","age":"???","addr":"abcdef"}
# a = urllib.parse.urlencode(data)
# print(a)  # urlencode的作用，将字典转化为 = 的形式，且中文变成%...
# print(urllib.parse.unquote(a))  # unquote,提取出


# 测试rsa
# msg = "1234"
# encrypt_text = rsa_encrypt(msg)
# print(encrypt_text)
# encrypt_text = [encrypt_text]
# decrypt_text = rsa_decrypt(encrypt_text)
# print(decrypt_text)

# 测试aes
# msg = "AES测试ABCD~!@#$"
# # key = os.urandom(16)  # 随机产生的aes秘钥
# # print(key)
# # print(base64.b64encode(key).decode())
# key = base64.b64decode("a7SDfrdDKRBe5FaN2n3Gfg==")
# encrypt_text = aes_encrypt(msg, key)
# print(encrypt_text)
# decrypt_text = aes_decrypt([encrypt_text], key)
# print(decrypt_text)

# print(base64.b64decode("EqB5ExC0QhErc3+JwJ2RcA==".encode()))
# # 测试使用rsa加密aes秘钥
# key = os.urandom(16)  # 随机产生的aes秘钥
# print(key)
# key_code = base64.b64encode(key).decode()
# print(key_code)
# # key = "lala"
# encrypt_text = rsa_encrypt(key_code)
# # print(encrypt_text)
# decrypt_text = rsa_decrypt([encrypt_text])
# print(decrypt_text)
# key = base64.b64decode(key_code)
# print(key)
# msg = "lala"
# encrypt_text = aes_encrypt(msg, key)
# print(encrypt_text)
# decrypt_text = aes_decrypt([encrypt_text], key)
# print(decrypt_text)

# 测试import，有换行和没有
# temp_key2 = b'-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMnhUpWMtPnDvcCQ\npBmGCaghcIRQ22hzw3BxBteys8icaRiGRS0TsrEYbA2dybgKr5mh9zaeZnelaVP8\nsJ36M99Ty1NS5Tr0JWunKqD01wLc1TbMqVtm9uYQBLv4J/33nnGiLfJfyjN7Nubz\nPVUWnkgAIxkgOCFBABw0QSAA0ZuXAgMBAAECgYABPNnb5gDQHNkL6VaLctA75437\nrwXs2hOUGZga8ZQWKGHty8PAXsvRchWzgeFqqStfykYKsJ9PIe8/dZkihNl8tl+3\nu4aE/Tle/uz5Wtl0pd5iGkaJFgBkpyJ/AY6MyYHbKD6GAp2TBBnK5GuIv1x3Gsq4\nqZpij3xp25tOAdZQqQJBAN6FT0AfhUYfpFz+yEvAF9AhLp8vwHvCDgnJ3i4AsiYI\nIw0R4LNl7y5/Qc7ANWqNxAL3zSaPM8xg3kvWq+p8TLkCQQDoQQNamjxEgOskvqrF\nSfaeagq4VTheSMD2pe1doaiXeMmqIbx0Xth3rxTszCUNyQFAXRnFKTHsdCIrH0E7\nlyLPAkAPfHWcf9UVoUQeGLk11GOT34tQFtGtiz7Q3ZSx3OiJDw3pbfIWaiSwNrkM\nu4G8LauTjU1gvpybP66Y1pLWWdo5AkBDD3qTb5NVSFAdBPy0CH4wEXhU7y5ecu1c\nil52OZY/Xj4EZMdQZo5kSGZnVS6hw1ccKYWmWxWyK3ouL1EbjrEbAkASX6Sk6NMb\nkvUdOuoJhqaAjjFXcBQ6JaCcV/J4cO3u2PLcrEnufcMc9cr2b+q4R8u05IJsElGX\ns1xcpI2K0DCh\n-----END ENCRYPTED PRIVATE KEY-----'
# temp_key = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSPgqqL+PoVyyBtOSpB58aO3rct7z9v6Cd0WqmSxn6vhtEzUUEUkJvipomutD7CDOkWYbYJ7w28lpmqzBkuGYxzpOZk4KLPAsD2sMtLsKI3YEaw8O1mowh0TlGYqgNaPara+bUhO1mHmQPMkoxOQvoQf8GJCQzXfPz/eBG2HGGawIDAQAB'
# key_bytes = bytes(temp_key, encoding="utf-8")
# key_bytes = b64decode(key_bytes)
# test_key1 = RSA.import_key(key_bytes)
# test_key2 = RSA.import_key(temp_key2)
# print(test_key1)
# print(test_key2)



# def test_for():
#     url = "http://172.20.62.202:8001/authen/test/"
#
#     request_headers = {
#         'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36 LBBROWSER'
#     }
#     key = os.urandom(16)  # 随机产生的aes秘钥
#     print(key)
#     before_amount = "100"
#     before_card = "5555 5555 5555 5555"
#     amount = aes_encrypt(before_amount, key)  # 先对信息用aes加密
#     print(amount)
#     card = aes_encrypt(before_card, key)
#     print(card)
#     key_code = base64.b64encode(key).decode()
#     print(key_code)
#     # print(base64.b64decode(key_code))
#     aes_key = rsa_encrypt(key_code)  # 对aes的秘钥key使用rsa加密
#     print(aes_key)
#     deal_identify = "711"
#     deal_identify = rsa_encrypt(deal_identify)
#     hash_info = md5(amount + card)  # 生成消息摘要
#     print(hash_info)
#     signature = create_sign_yt(hash_info)
#     print(signature)
#     # if verify_sign_yt(hash_oi, signature):
#     #     print("lala")
#
#     # print(d)
#     # amount = 1
#     # card = 2
#     # aes_key = 3
#     # signature = 4
#     form_data = {
#         "amount": amount,
#         "card": card,
#         "aes_key": aes_key,
#         "deal_identify": deal_identify,
#         "signature": signature,
#     }
#
#     form_data = urllib.parse.urlencode(form_data).encode()
#
#     req = urllib.request.Request(url, data=form_data, headers=request_headers)
#
#     response = urllib.request.urlopen(req)

# test_for();

# print(md5("VTdGbNl5JH0Sgr6GkdmV3A==r8nFJL1tmdgVw1Q zLXWz5ijTeJ9qgFsyOmUF0cwK/4="))



# ss=rsa_decrypt_yt(["ZxKLOydhZmWFs3b2jTQUxAowhcH8cmYwxYsdjCyxCyDLJDxE7aUBqxhuTJBCQ4HMP/WQVHvm7Lzmv33klL3c436rfjx9eyaSArVtggN6I1Srl5aqp5xyhchWrYdQK0r5o+mHwc6gyl3Ix2pdJwZ7nijRwdNms2ayC+S3YiYt3iU="])
# print(ss)
#
# print(verify_sign_yt('MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJ9ozEqK2l/BkFmt ZTlo2/L+1gfLfDcWujNdXDmhdG/RPltsuZOQcWm3onPsGABmSx/QhLAdR8HLf9pi YUzBU3Ielis+I9hiYGItojrHKnK+Hhq67rTcW+IQ4hCmCEPDscnmupUZeUjVIUxa t2cnrNQvZpyt+KEwJRUfleUB55bxAgMBAAECgYA8fOOoFXAvjZ9cp/MVCbkMR66n XotPzAvzmaV5KM6p71geEO+KEvE2EDxQiHHDFQ3EkLcIrNOhsbpd/560JVeoCJbP bEPHYkCLVuy5eOj17FCq+5Wi/45Ex3jPZM2fsUauaq1wqBg5gDZgFEANm56YNAhm u+/K90jql72Iacc0UQJBANDEjfP2oPvEPEUvs1CnrV27LYIqyZSjwBhOB0HQl9l1 LMze9N+qB5DfI1N8xMgY1VAeLk0lOaaYhMqLBL+YT/MCQQDDeX6fQeQeglA+bNez bai0Mm1H6YdUjbdtV0/Jyqt5LinfYzBUuwU5t+ItEdl42+SoBEEJ1UTLBbrHg7Bg dJqLAkA7YX0DBIabtiByiXPWoCsGuyPhn2wA9GbCQwd7Z+qZNuQMTeqW59UJFv8E UzvhsnaSOFNxLAJu6Xjz54DtQlSTAkEAq2I2doNa8rTmjhT3+cVHiNY9ojNKCARI soE+33nmZdTnuYhJs8BVkIl8sG9Z8PE6xWUVcP2f1zEq1grL9YXGiQJAdkYxon8q p/1UzpTIz20eN0vWSyuGxIy3VTD5xAeXFXG4rhbF6Oe7itWwUFKu9gl1FSqhgv3t HTFObu41baewQA==',
#                   "ifJBgOgt0iJmwr252B2eUXrfEPxIgao9f9mObVrsG6kjzSy1Cnvg8KWQWKKVYKD0OBtKWtf/n2QFXHh3Qe6BVJHNYFXj1vu4ATYdIZrmFBs+MFDgwi0maN3yTMXKZ2YY9yrdvKJJbBUHRLKG5iTa2GcTIZcEdyCDshB1iU3hNVU=","CA"))

# yy = base64.b64decode("a7SDfrdDKRBe5FaN2n3Gfg==")
# print(yy)
# aes_decrypt(["MH2eiaR5Oo/K5/pmONTXIsCHraHVU992BzbOcmD4OBk="], yy)


# 验签证书BANK
message = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDf7cQzFGrPgBkg+D6M1U7XdddN gIlFiATQFcwvi24ZDcSu2ynFzuuoJURPIuqM8XNwATFIZ/pU4ZmouBUgzFwshUJg UFQArscNQFD1EKmHuKY0pmi2dFHhxt51YOrSu1ozBOI1u/NM4OYX4KBzhVc6o4pS iej1zqBLr3iNaDE4kwIDAQAB"
sign = "CPA2yD+OVY6dyhUaHxGDEkb1senvHS0+9WhDPbSQfARc7MiQwEr/HUrHIwBWPVv+5VbPfnLQTezj7VowtWPvjuk57G2B8OJM9FFE+RmZCSUCg5PsCRemj9oNz6A5qrX6BCKjLWolZAjOVVls4eqNJk3iBKNfCr3ckyVthaxOoKU="
print(verify_sign_yt(message, sign, "CA"))


# 验签证书E-SHOP
message = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDstiYKiePxsEJOiLskFkxwcGPC SUIHE4cmO0WWzC60zRQYEkUxRauwQoVbe+6wiVgSyDn3yvezfdMja8wTPaUsPh3i GYJPWAxZlH5fjv5G02r73LbFJLgveUIjSgykN50smt6S4+fzXg41nrp5Vasg9t9S NzjjU7XTYSG+75EuJwIDAQAB"
sign = "YhC/hXt+jIOAPN2Cq21rVi9csyqlIp/WJan9T1V8OFxHzQ3r5D2XXDHOd3VyIKxyncjA8TEctUynJuJ2gvGLoQ+8mxAUuiLOWlmogeDmjM+EhrU/puOoPjAddDqXn2EI6O+LFZV8Ey4f47CYNAlDpig3VEl+NSI+w2cZxLmHPVs="
print(verify_sign_yt(message, sign, "CA"))

