# Generated by Django 3.2.8 on 2021-11-23 06:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userPage', '0002_alter_product_image'),
    ]

    operations = [
        migrations.RenameField(
            model_name='ledger',
            old_name='when',
            new_name='whenn',
        ),
        migrations.AlterField(
            model_name='ledger',
            name='confirmedBy',
            field=models.CharField(max_length=100, verbose_name='승인자'),
        ),
    ]
