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
    deptNo = models.ForeignKey(
        'Dept',
        on_delete=models.SET_DEFAULT,
        default=0
    )
    phone = models.CharField(verbose_name='전화번호', max_length=100)

    def setPW(self, inpw):
        self.password = bcrypt.hashpw(bytes(inpw, encoding='utf-8'), salt=bcrypt.gensalt())

    def chkPW(self, inpw):
        return bcrypt.checkpw(bytes(inpw, encoding='utf-8'), self.password)


class Dept(models.Model):
    deptNo=models.IntegerField(
        verbose_name='부서 번호',
        primary_key=True,
        unique=True,
    )
    deptName = models.CharField(
        verbose_name='부서명',
        max_length=50
    )
