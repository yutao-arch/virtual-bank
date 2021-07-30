from django.db import models


class User(models.Model):
    # 个人信息表
    name = models.CharField(max_length=25)  # 用户名
    id_no = models.CharField(max_length=18)  # 身份证
    card = models.CharField(max_length=20)  # 银行卡
    phone = models.CharField(max_length=11)  # 手机号
    passwd = models.CharField(max_length=50)  # 登录密码
    pay_passwd = models.CharField(max_length=50)  # 支付密码
    pub_key = models.FilePathField(  # 公钥路径
        path="C:\\Users\\yutao\\PycharmProjects\\virtualBank\onlineBank\\authenticate\\rsa\\", blank=True, null=True)

    def __str__(self):
        return str(self.name) + ', phone:' + str(self.phone)


class Account(models.Model):
    # 账户相关信息
    user = models.CharField(max_length=11)  # 手机号
    avatar = models.ImageField(upload_to='avatar')  # 头像路径
    balance = models.FloatField()  # 余额
    cost = models.FloatField()  # 支出总额
    regtime = models.DateField(auto_now_add=True)  # 注册时间

    def __str__(self):
        return str(self.user) + ', balance:' + str(self.balance)


class bankpayBill(models.Model):
    #  商家的支付信息
    amount = models.CharField(max_length=10)  # 支付金额
    card = models.CharField(max_length=20)  # 收款人卡号
    aes_key = models.CharField(max_length=100)  # 与商家协商AES秘钥
    deal_identify = models.CharField(max_length=10)  # 此次交易的订单号（需要支付后发给商家用于防重放）
    pay_id = models.CharField(max_length=5)  # 支付订单号
    hash_info = models.CharField(max_length=100, blank=True, null=True)  # 商家传来的amount和card的hash
    hash_pi = models.CharField(max_length=100, blank=True, null=True)  # 支付信息的哈希
    payer_name = models.CharField(max_length=25, blank=True, null=True)  # 付款人的用户名
