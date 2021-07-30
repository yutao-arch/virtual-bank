from django.urls import path
from . import views

urlpatterns = [
    path('<str:name>/', views.manage, name='manage'),
    path('Salt/<str:name>/', views.salt, name='salt'),
    path('Recharge/<str:name>/', views.recharge, name='recharge'),
    path('Withdraw/<str:name>/', views.withdraw, name='withdraw'),
    path('Transfer/<str:name>/', views.transfer, name='transfer'),
    path('Bills/<str:name>/', views.bills, name='bills'),
    path('Info/<str:name>/', views.info, name='info'),
    path('Edit/<str:name>/', views.edit, name='edit'),
    path('Logout/<str:name>/', views.logout, name='logout'),
]
