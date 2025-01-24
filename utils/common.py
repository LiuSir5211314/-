# 登录认证装饰器
from django.shortcuts import redirect


def login_request(func):
    def wrapper(request, *args, **kwargs):
        is_login = request.session.get('username',None)
        if is_login:
            return func(request, *args, **kwargs)
        else:
            return redirect('/')

    return wrapper