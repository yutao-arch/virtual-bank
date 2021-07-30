from django.db import models


# Create your models here.

class Bills(models.Model):
    """
    存储所有交易的数据表单、包括提现、转账在内的四种账单类型
    """
    payer = models.CharField(max_length=10)  # 付款人的用户名
    payer_card = models.CharField(max_length=20)  # 付款人卡号
    beneficiary = models.CharField(max_length=20)  # 收款人卡号
    amount = models.FloatField()  # 交易金额
    bill_type = models.CharField(max_length=8)  # 交易类型
    date = models.DateTimeField(auto_now_add=True)  # 交易日期

    def __str__(self):
        return 'payer:' + str(self.payer) + 'beneficiary:' + str(self.beneficiary)
