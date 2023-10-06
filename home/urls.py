from django.urls import path, include
from .views import (
    home_page,
    register_page,
    login_page,
    logout_page,
    login_from_uid,
    reset_view, 
    reset_from_uid,
    dashboard_page,
error_page,
send_msg,
receive_msg
    )

urlpatterns = [
    path('', home_page, name='home'),
    path('dashboard/', dashboard_page, name='dashboard'),
    path('register/', register_page, name='register'),
    path('login/', login_page, name='login'),
    path('login/<str:uid>', login_from_uid, name='login_uid'),
    path('logout/', logout_page, name='logout'),
    path('reset/', reset_view, name='reset'),
    path('reset/<str:uid>', reset_from_uid, name='reset_uid'),
    path('error/',error_page, name='error_page'),
    path('dashboard/send_msg',send_msg,name='send_msg'),
    path('dashboard/receive_msg',receive_msg, name='receive_msg'),
]

