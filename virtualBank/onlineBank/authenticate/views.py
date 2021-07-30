import logging
import os
import random
import base64

from Crypto.PublicKey import RSA
from django.http import JsonResponse
from django.shortcuts import HttpResponse, redirect, render
from django.urls import reverse

from onlineBank.config import Config
from onlineBank.utils import aes_decrypt, creat_bill, get_account_by_card, get_rsa_pubkey, \
    get_user_by_card, md5, rsa_decrypt, set_salt, verify_sign, get_account, \
    get_user, verify_sign_yt, rsa_decrypt_yt, create_sign_yt, rsa_encrypt_yt, get_salt
from .models import Account, User, bankpayBill

logger = logging.getLogger('balance')


def register(request):
    # 返回注册页面
    return render(request, "authenticate/register.html")


def su_request(request):
    # 用于注册时请求的处理
    if request.method == "POST":  # 对于POST的请求
        signup = request.POST.get('signup_request')
        if signup == "true":  # 当signin.js里面定义的signup_request为true时，返回创建服务器的rsa公钥到前端
            if not os.path.exists(Config.key_url + "RSA_private.pem"):
                key = RSA.generate(1024)
                encrypted_key = key.exportKey(pkcs=8, protection="scryptAndAES128-CBC")
                with open(
                        Config.key_url + "RSA_private.pem",
                        "wb+") as f:
                    f.write(encrypted_key)
                with open(
                        Config.key_url + "RSA_public.pem",
                        "wb+") as f:
                    f.write(key.publickey().exportKey())
            return JsonResponse({"pub_key": get_rsa_pubkey()})
        else:  # 当signin.js里面定义的signup_request为false时将得到的数据用rsa私钥进行解密，
               # 然后对密码使用md5进行哈希散列，
               # 然后返回saved=True到前端
            # 从请求中得到所有加密后的信息
            name = request.POST.get('name')
            phone = request.POST.get('phone')
            card = request.POST.get('card')
            id_no = request.POST.get('id_no')
            passwd = request.POST.get('passwd')
            cipher_data = [name, id_no, phone, card, passwd]
            plaintext = rsa_decrypt(cipher_data)  # 使用私钥解密
            User.objects.get_or_create(name=plaintext[0], id_no=plaintext[1], phone=plaintext[2], card=plaintext[3],
                                       passwd=md5(plaintext[4]), pay_passwd='12345678')
            Account.objects.get_or_create(user=plaintext[2], avatar="avatar/48.jpg", balance="0", cost="0")
            return JsonResponse({"saved": True})


def signin(request):
    # 用于登录
    if request.method == "POST":
        signin = request.POST.get("si_request")
        if signin == "true":  # 当signin.js里面定义的si_request为true时，返回rsa公钥和盐值到前端
            [salt_id, salt] = set_salt(request)  # 生成盐值
            return JsonResponse({"pub_key": get_rsa_pubkey(), "salt": salt, "salt_id": salt_id})
        else:  # 当signin.js里面定义的si_request为false时，返回要跳转的url和可能会出现的message，if_success或者对于没有设置支付密码的set_paypasswd到前端
            # 从请求中得到所有加密后的信息和salt_id
            name = request.POST.get("name")
            passwd = request.POST.get("passwd")
            salt_id = request.POST.get("salt_id")
            if not name or not passwd:  # 对用户名或者密码不存在的情况
                return JsonResponse({"message": "用户名或密码不存在"})
            plaintext = rsa_decrypt([name, passwd])
            passwd = plaintext[1]
            try:
                passwd_of_models = User.objects.values("passwd").get(name=plaintext[0]).get("passwd")  # 得到数据库中该用户的密码
                corr_pass = md5(passwd_of_models + request.session[salt_id])  # 对该密码加上对应的盐值然后使用MD5哈希散列，防重放
                if passwd == corr_pass:  # 对于密码匹配成功的情况
                    user = request.session.get(plaintext[0], None)
                    # if user and user['is_login']:
                    #     message = "你已经登录过了"
                    #     return JsonResponse({"message": message})
                    del request.session[salt_id]  # 验证之后删除盐值
                    request.session[plaintext[0]] = {'is_login': True, 'user_name': plaintext[0]}
                    request.session.set_expiry(0)
                    pay_passwd = User.objects.values("pay_passwd").get(name=plaintext[0]).get("pay_passwd")  # 得到数据库中该用户的支付密码
                    if not pay_passwd or pay_passwd == '12345678':  # 如果没有支付密码或者为初始密码
                        url = reverse("set_paypasswd", kwargs={"name": plaintext[0]})
                        return JsonResponse({"if_success": True, "url": url})  # 返回if_success为True和填写支付密码的url到前端
                    return JsonResponse({"if_success": True, "url": reverse("manage", kwargs={"name": plaintext[0]})})  # 正常登陆情况下返回if_success为True和用户操作界面的url到前端
                else:
                    message = "密码错误"
            except User.DoesNotExist:
                message = " 该用户不存在"
        return JsonResponse({"message": message})  # 返回message到前端
    else:
        return render(request, "authenticate/signin.html")


def prompt(request):
    # 用于确认登录成功
    return render(request, "authenticate/prompt.html")


def set_paypasswd(request, name):
    # 设置支付密码
    user = request.session.get(name, None)  # 得到请求中的用户名
    if not (user and user.get('is_login', None)):  # 当用户还没有登录时，直接进入登录页面
        return render(request, "authenticate/signin.html")
    if request.method == 'POST':
        set_pay = request.POST.get('set')
        if set_pay == 'true':  # 当setpay.js里面定义的set为true时，返回RSA公钥到前端
            return JsonResponse({"pub_key": get_rsa_pubkey()})
        else:  # 当setpay.js里面定义的set为false时，返回要跳转的url和可能会出现的message到前端
            passwd = request.POST.get("passwd")
            if not passwd:  # 密码不存在时
                return JsonResponse({"message": "密码不能为空"})
            pay_passwd = rsa_decrypt([passwd])[0]  # 将密码使用RSA私钥解密
            if pay_passwd == '12345678' or pay_passwd == '':  # 密码太简单时
                return JsonResponse({"message": "密码太简单", "url": ''})
            else:
                the_user = User.objects.get(name=name)
                the_user.pay_passwd = md5(pay_passwd)  # 将解密后的密码使用MD5哈希加密后存入数据库中
                the_user.save()
                return JsonResponse({"message": "密码已经保存", "url": reverse("manage", kwargs={"name": name})}) # 返回要跳转的url和message到前端
    return render(request, "authenticate/setpay.html")


def deal(request):
    # 用于读取处理商家的转账请求
    if request.method == "GET":
        amount = request.GET.get("amount")  # AES加密后的金额
        card = request.GET.get("card")  # AES加密后的收款方卡号
        key = request.GET.get("aes_key")  # RSA加密后的aes_key
        deal_identify = request.GET.get("deal_identify")  # RSA公钥加密的订单号
        hash_info = md5(amount + card)  # 商家传来信息的哈希
        signature = request.GET.get("signature")  # 商家签名
        pay_id = random.randint(Config.min_payId, Config.max_payId)  # 随机生成一个支付标识符
        if verify_sign_yt(hash_info, signature, Config.Plat_name):
            [aes_key] = rsa_decrypt_yt([key])
            real_key = base64.b64decode(aes_key)
            [deal_identify] = rsa_decrypt_yt([deal_identify])
            [amount, card] = aes_decrypt([amount, card], real_key)
            bankpayBill.objects.create(amount=amount, card=card, aes_key=aes_key,
                                       deal_identify=deal_identify, pay_id=pay_id,
                                       hash_info=hash_info)  # 在数据库中创建该账单
            pay_id = '%d' % pay_id
            send_pay_id = rsa_encrypt_yt(pay_id, "ESHOP")  # 用商城的公钥加密pay_id,发送给商家
            send_signature = create_sign_yt(send_pay_id)  # 银行产生签名给商城
            return redirect(Config.Plat_PayHost + "?send_pay_id=" + send_pay_id + "&send_signature=" + send_signature)
        else:
            return redirect(Config.Plat_PayHost)  # 如果验签失败，不返回pay_id等信息给商家
    return HttpResponse("NULL")


def pay(request, pay_id):
    # 用户付款
    info_dict = bankpayBill.objects.get(pay_id=pay_id)  # 从数据库中读出该账单
    if request.method == "POST":
        if_has_private = request.POST.get("if_has_private")
        if if_has_private == "false":
            # 读取前端传来的各种信息
            phone = request.POST.get("phone")
            plaintext = rsa_decrypt([phone])
            phone = plaintext[0]
            try:
                user = User.objects.get(phone=phone)  # 在User数据库中找到该用户
                return JsonResponse({"name": user.name})
            except:
                return JsonResponse({"message": "没有该用户"})
        else:
            phone = request.POST.get("phone")
            passwd = request.POST.get("passwd")
            signature = request.POST.get("signature")
            name = request.POST.get("name")
            if verify_sign([phone, passwd], signature, name):  # 验证前端用用户私钥的签名
                plaintext = rsa_decrypt([phone, passwd])
                user = User.objects.get(phone=plaintext[0])
                salt = request.session.get("temp_salt")  # 盐值用来防重放
                if plaintext[1] == md5(user.pay_passwd + salt):
                    # 将付款信息读进数据库
                    info_dict.payer_name = user.name
                    info_dict.hash_pi = md5(phone+passwd)
                    info_dict.save()
                    amount = info_dict.amount
                    card = info_dict.card
                    beneficiary = get_account_by_card(card)  # 得到收款人的卡号
                    money = float(amount)
                    user_name = info_dict.payer_name
                    user = get_user(user_name)
                    account = get_account(user_name)
                    if account.balance < money:
                        message = "账户余额不足"
                        return JsonResponse({"if_success": False, "message": message})
                    elif not creat_bill(user.name, card, money, "transfer"):
                        message = "创建账单失败"
                        return JsonResponse({"if_success": False, "message": message})
                    else:
                        account.balance -= money  # 进行金额的操作
                        account.cost += money
                        account.save()
                        beneficiary.balance += money
                        beneficiary.save()
                        message = "你已经支付了 " + amount + " 元"
                        del request.session["temp_salt"]  # 删除session值，防重放
                        deal_identify = info_dict.deal_identify
                        send_deal_identify =rsa_encrypt_yt(deal_identify, "ESHOP")  # 支付成功后需要反馈给商城：商城RSA公钥加密的订单号
                        to_go_url = Config.Plat_GoHost + "?send_deal_identify=" + send_deal_identify  # 商城接受成功支付信息的url，返回的为send_deal_identify
                        logger.info('user: %s operation:%s amount:%s $ to beneficiary:%s' % (name, 'transfer', str(amount), beneficiary.user))
                        return JsonResponse({"if_success": True, "message": message, "to_go_url": to_go_url})
                else:
                    message = "密码错误"
                    return JsonResponse({"if_success": False, "message": message})
            else:
                message = "验证签名失败"
                return JsonResponse({"if_success": False, "message": message})
    # 从数据库中读出账单中的各种信息
    request.session["temp_salt"] = get_salt(Config.salt_Length)  # 产生一个随机盐值，用于防止防重放攻击
    temp_salt = request.session.get("temp_salt")
    card = info_dict.card
    amount = info_dict.amount
    user = get_user_by_card(card)
    name = user.name  # 收款人姓名
    account = get_account_by_card(card)
    avatar = account.avatar
    return render(request, "authenticate/pay.html", {"amount": amount, "name": name, "image": avatar, "pay_id": pay_id, "temp_salt": temp_salt})


def verify(request, name):
    # 用于在银行端用户输入私钥身份验证的身份认证
    user = request.session.get(name, None)
    if not (user and user.get('is_login', None)):  # 对于用户不存在和用户还没有登录的情况，返回到登录页面
        return render(request, "authenticate/signin.html")
    return render(request, "authenticate/verify.html", {"name": name})


def verify_for_pay(request, pay_id, name):
    # 用于在商家端付款时用户输入私钥身份验证的身份认证
    return render(request, "authenticate/verify_for_pay.html", {"pay_id": pay_id, "name": name})

