from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import LoginInfo, msgInfo

admin.site.register(LoginInfo)
admin.site.register(msgInfo)