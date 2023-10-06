from django.db import models
from django.contrib.auth.models import User

class LoginInfo(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    fails = models.PositiveSmallIntegerField(default=0)
    login_link = models.CharField(unique=True, blank=True, null=True, max_length=225)
    reset_link = models.CharField(unique=True, blank=True, null=True, max_length=225)

    def __str__(self):
        return self.user.username

class msgInfo(models.Model):
    sender = models.CharField(blank=False,null=False, max_length=255)
    receiver = models.CharField(blank=False,null=False, max_length=255)
    msg = models.TextField()

#a = User.objects.only('username')
# for user in a:
    #print(user.username)