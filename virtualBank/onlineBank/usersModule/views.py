import logging

from authenticate.models import Account
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from onlineBank.config import Config
from onlineBank.utils import creat_bill, get_account, get_user, get_userby_phone, if_login, md5, rsa_decrypt, set_salt, \
    verify_sign

from .models import Bills

logger = logging.getLogger('balance')


def manage(request, name):
    # 个人主页
    if not if_login(request, name):  # 当用户还没登录时，返回登录页面
        return redirect(reverse('signin'))
    # 从数据库中得到用户的各种信息
    account = get_account(name)
    outcome = account.cost
    balance = account.balance
    image = account.avatar
    return render(request, "usersModule/manage.html",
                  {"name": name, "outcome": outcome, "income": balance, "image": image})


def salt(request, name):
    # 向前端返回一个随机的salt值并设置在对应的session中
    salt = set_salt(request, name)
    return JsonResponse({"salt": salt})


def recharge(request, name):
    # 为账户存款
    if not if_login(request, name):  # 当用户还没登录时，返回登录页面
        return redirect(reverse('signin'))
    # 从数据库中得到用户的各种信息
    user = get_user(name)
    account = get_account(name)
    card = user.card
    image = account.avatar
    if request.method == "POST":
        # 得到前端传来的各种信息：加密后的充值金额，加密后的支付密码，数字签名和盐值
        amount = request.POST.get("amount")
        passwd = request.POST.get("passwd")
        signature = request.POST.get("signature")
        salt = request.session[name]['salt']
        # print(salt)
        plaintext = rsa_decrypt([amount, passwd])  # 解密
        success = ""
        money = float(plaintext[0])
        if money < 0:  # 对充值金额小于0的情况
            return JsonResponse({"message": "存款金额不能为0"})
        if verify_sign([amount, passwd], signature, name):
            if md5(user.pay_passwd + salt) == plaintext[1]:  # 用户密码匹配的情况，盐值是为了防重放攻击
                if not creat_bill(name, "", money, "recharge"):
                    return JsonResponse({"message": "创建账单错误"})
                del request.session[name]['salt']  # 清空session中的salt值，防重放
                account.balance += money
                account.save()
                logger.info('user: '+name+' operation: '+'recharge amount: '+str(money)+'$')
                message = "你的账户刚刚存入了" + plaintext[0] + " 元, 将返回到主页"
                success = True
            else:
                message = "密码错误"
        else:
            message = "签名验证失败"
        return JsonResponse({"message": message, "success": success})
    return render(request, "usersModule/Recharge.html", {"name": name, "card": card, "image": image})


def withdraw(request, name):
    # 取款
    if not if_login(request, name):  # 当用户还没登录时，返回登录页面
        return redirect(reverse('signin'))
    # 从数据库中得到用户的各种信息
    user = get_user(name)
    account = get_account(name)
    card = user.card
    image = account.avatar
    if request.method == "POST":
        # 得到前端传来的各种信息：加密后的取款金额，加密后的支付密码，数字签名和盐值
        amount = request.POST.get("amount")
        passwd = request.POST.get("passwd")
        signature = request.POST.get("signature")
        salt = request.session[name]['salt']
        plaintext = rsa_decrypt([amount, passwd])  # 解密
        success = ""
        money = float(plaintext[0])
        if money < 0:
            return JsonResponse({"message": "取款金额不能为0"})
        if verify_sign([amount, passwd], signature, name):
            if md5(user.pay_passwd + salt) == plaintext[1]:  # 用户密码匹配的情况，盐值是为了防重放攻击
                if account.balance < money:
                    message = "账户余额不足"
                    return JsonResponse({"message": message})
                if not creat_bill(name, "", money, "withdraw"):
                    return JsonResponse({"message": "创建账单错误"})
                del request.session[name]['salt']  # 清空session中的salt值，防重放
                account.balance -= money
                account.cost += money
                account.save()
                logger.info('user: %s operation:%s amount:%s $' % (name, 'withdraw', str(money)))
                message = "你的账户刚刚取走了 " + plaintext[0] + " 元, 将返回主页"
                success = True
            else:
                message = "密码错误"
        else:
            message = "签名验证失败"
        return JsonResponse({"message": message, "success": success})
    return render(request, "usersModule/Withdraw.html", {"name": name, "card": card, "image": image})


def transfer(request, name):
    # 转账
    if not if_login(request, name):  # 当用户还没登录时，返回登录页面
        return redirect(reverse('signin'))
    # 从数据库中得到用户的各种信息
    user = get_user(name)
    account = get_account(name)
    card = user.card
    image = get_account(name).avatar
    if request.method == "POST":
        # 得到前端传来的各种信息：加密后的转账金额，加密后的支付密码，加密后的两个电话号码，盐值和数字签名
        amount = request.POST.get("amount")
        passwd = request.POST.get("passwd")
        b_phone = request.POST.get("b_phone")
        phone = request.POST.get("phone")
        salt = request.session[name]['salt']
        signature = request.POST.get("signature")
        ciphers = [amount, passwd, b_phone, phone]
        plaintext = rsa_decrypt(ciphers)  # 解密
        success = ""
        try:  # 对于用户不存在的情况
            beneficiary = Account.objects.get(user=plaintext[2])
        except:
            return JsonResponse({"message": "没有该用户"})

        if verify_sign(ciphers, signature, name):
            if md5(user.pay_passwd + salt) == plaintext[1]: # 用户密码匹配的情况，盐值是为了防重放攻击
                money = float(plaintext[0])
                if money < 0:
                    return JsonResponse({"message": "转账金额不能小于0"})
                if account.balance < money:
                    return JsonResponse({"message": "账户余额不足"})
                if not creat_bill(name, get_userby_phone(beneficiary.user).card, money, "transfer"):
                    return JsonResponse({"message": "创建账单错误"})
                del request.session[name]['salt']  # 清空session中的salt值，防重放
                account.balance -= money
                account.cost += money
                account.save()
                beneficiary.balance += money
                beneficiary.save()
                logger.info('user: %s operation:%s amount:%s $ to beneficiary:%s' % ( name, 'transfer', str(money), beneficiary.user))
                message = "你成功转账 " + plaintext[0] + " 元, 将返回主页"
                success = True
            else:
                message = "密码错误"
        else:
            message = "签名验证失败"
        return JsonResponse({"message": message, "success": success})
    return render(request, "usersModule/Transfer.html", {"name": name, "card": card, "image": image})


def bills(request, name):
    # 查看账单
    if not if_login(request, name):  # 当用户还没登录时，返回登录页面
        return redirect(reverse('signin'))
    # 从数据库中得到用户的各种信息，传到前端进行展示
    user = get_user(name)
    account = get_account(name)
    image = account.avatar
    outs = list(Bills.objects.filter(payer_card=user.card))
    outs.reverse()
    incomes = list(Bills.objects.filter(beneficiary=user.card))
    incomes.reverse()
    return render(request, "usersModule/Bills.html",
                  {"name": name, "image": image, "outs": outs[0:Config.max_num], "incomes": incomes[0:Config.max_num]})


def info(request, name):
    # 查看个人信息和设置头像
    if not if_login(request, name):  # 当用户还没登录时，返回登录页面
        return redirect(reverse('signin'))
    # 从数据库中得到用户的各种信息
    user = get_user(name)
    account = get_account(name)
    if request.method == "POST":  # 如果收到了前端传来的POST请求
        file = request.FILES['avatar']  # 修改用户头像路径
        if file:
            account.avatar = file
            account.save()
    card = user.card  # 各种需要传到前端的数据
    phone = user.phone
    time = account.regtime
    image = account.avatar
    return render(request, "usersModule/Info.html",
                  {"name": name, "card": card, "phone": phone, "time": time, "image": image})


def edit(request, name):
    # 修改个人信息
    if not if_login(request, name):  # 当用户还没登录时，返回登录页面
        return redirect(reverse('signin'))
    # 从数据库中得到用户的各种信息
    user = get_user(name)
    account = get_account(name)
    image = account.avatar
    if request.method == "POST":
        # 得到前端传来的各种信息：加密后个人信息
        ppasswd = request.POST.get("ppasswd", None)
        card = request.POST.get("card", None)
        phone = request.POST.get("phone", None)
        passwd = request.POST.get("passwd", None)
        opasswd = request.POST.get("opasswd", None)
        success = False
        # 在后端对这些信息解密
        if opasswd :
            opasswd = rsa_decrypt([opasswd])[0]
            if user.pay_passwd == md5(opasswd):  # 旧的密码验证成功时，针对各种情况选择是否更新个人信息
                if ppasswd:
                    user.pay_passwd = md5(rsa_decrypt([ppasswd])[0])
                if card:
                    user.card = rsa_decrypt([card])[0]
                if phone:
                    phone = rsa_decrypt([phone])[0]
                    user.phone = phone
                    account.user = phone
                if passwd:
                    user.passwd = md5(rsa_decrypt([passwd])[0])
                user.save()
                account.save()
                message = "修改个人信息成功"
                success = True
            else:
                message = "密码错误"
        else:
            message = "旧密码不能为空"
        return JsonResponse({"message": message, "success": success})
    return render(request, "usersModule/Edit.html", {"name": name, "image": image})


def logout(request, name):
    # 退出登录
    user = request.session.get(name, None)
    if user:
        del request.session[name]
    return render(request, "authenticate/signin.html")
