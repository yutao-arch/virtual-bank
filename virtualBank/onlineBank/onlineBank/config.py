class Config:

    key_url = "C:\\Users\\yutao\\PycharmProjects\\virtualBank\\onlineBank\\authenticate\\rsa\\"
    # 所有公钥和服务器RSA公钥私钥的储存路径

    max_num = 10  # Bill页数的最大值

    max_saltId = 20  # 盐Id的最大值
    salt_Length = 8  # 盐的长度

    max_payId = 10000  # 随机生成的最大payId，支付标识符
    min_payId = 0  # 随机生成的最小payId

    Base_DIR = "C:\\Users\\yutao\\PycharmProjects\\virtualBank\\onlineBank\\onlineBank\\log"  # 日志log的位置

    Plat_Host = "http://172.20.43.37:8080/"  # 商城的host
    Plat_PayHost = Plat_Host+"E-shop/payment_servlet"  # 商城接受pay_id的页面
    Plat_GoHost = Plat_Host+"E-shop/success_servlet"  # 商城接受支付成功和订单号的页面
    Plat_name = "ESHOP"  # 商城的的公钥的用户名

    User_Agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 ' \
                 '(KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36 LBBROWSER'  # Post头部
