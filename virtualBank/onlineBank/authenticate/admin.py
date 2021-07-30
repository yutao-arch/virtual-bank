from django.contrib import admin
from .models import User, Account, bankpayBill

# Register your models here.
admin.site.register(User)
admin.site.register(Account)
admin.site.register(bankpayBill)



class Admin(admin.ModelAdmin):
    readonly_fields = ('regtime',)
