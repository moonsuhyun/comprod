import os

from django.db import models
from comprod import settings
# Create your models here.


class Product(models.Model):
    name = models.CharField(verbose_name='품목명', max_length=100)
    cls = models.CharField(verbose_name='분류', max_length=100)
    stock = models.IntegerField(verbose_name='재고수량')
    image = models.ImageField(verbose_name='이미지', upload_to="images/", blank=True)

    def __str__(self):
        return str(self.id)

    def inout(self, quantity):
        if self.stock + quantity > 0:
            self.stock += quantity
        return self.stock

    def delete(self, *args, **kwargs):
        super(Product, self).delete(*args, **kwargs)
        os.remove(os.path.join(settings.MEDIA_ROOT, self.image.path))


class Ledger(models.Model):
    who = models.CharField(verbose_name='신청자', max_length=100)
    what = models.IntegerField(verbose_name='신청품목')
    whenn = models.DateTimeField(verbose_name='신청일', auto_now_add=True) # SQL 충돌..
    quantity = models.IntegerField(verbose_name='수량')
    type = models.BooleanField(verbose_name='유형')  # ture=입고, false=출고
    confirmedBy = models.CharField(verbose_name='승인자', max_length=100)
    comment = models.TextField(verbose_name='코멘트')

    def __str__(self):
        return str(self.id)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.quantity > 0:
            self.type = True
        elif self.quantity < 0:
            self.type = False
