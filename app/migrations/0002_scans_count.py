# Generated by Django 3.2.8 on 2022-10-08 13:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scans',
            name='count',
            field=models.IntegerField(default=0, verbose_name='文本长度'),
        ),
    ]
