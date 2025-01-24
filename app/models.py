from django.db import models


# Create your models here.
class Scans(models.Model):
    id = models.AutoField(primary_key=True)
    ip = models.CharField('ip地址', default='', max_length=50)
    port = models.CharField('端口', default='123', max_length=50)
    problem = models.TextField('问题', default='')
    count = models.IntegerField('文本长度',default=0)
    create_time = models.DateTimeField('检测时间', auto_now_add=True)
    description = models.TextField('描述', default='')

    def __str__(self):
        return self.port

    class Meta:
        db_table = 'scans'
