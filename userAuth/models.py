from django.db import models
import bcrypt


class User(models.Model):
    id = models.CharField(
        verbose_name='아이디',
        primary_key=True,
        max_length=100,
        unique=True,
        error_messages={
            'unique': "해당 아이디가 이미 존재합니다."
        }
    )
    pw = models.CharField(verbose_name='비밀번호', max_length=100)
    isAdmin = models.BooleanField(verbose_name='관리자여부')
    name = models.CharField(verbose_name='이름', max_length=100)
    dept = models.CharField(verbose_name='부서명', max_length=100)
    phone = models.CharField(verbose_name='전화번호', max_length=100)
    isConfirmed = models.BooleanField(verbose_name='승인여부', default=0)
    joinDate = models.DateTimeField(verbose_name='가입일자', auto_now_add=True)

    def __str__(self):
        return self.id

    def setPW(self, inpw):
        self.pw = (bcrypt.hashpw(bytes(inpw, encoding='utf-8'), salt=bcrypt.gensalt())).decode('utf-8')

    def checkPW(self, inpw):
        return bcrypt.checkpw(bytes(inpw, encoding='utf-8'), bytes(self.pw, encoding='utf-8'))



