import datetime
import platform

import psutil
from django.core.paginator import Paginator
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from user.models import User
from utils.common import login_request
import requests
import subprocess
import os
from .models import Scans
from .tests import translateBaidu


def login(req):
    """
    跳转登录
    :param req:
    :return:
    """
    return render(req, 'login.html')


def register(req):
    """
    跳转注册
    :param req:
    :return:
    """
    return render(req, 'register.html')


@login_request
def index(req):
    """
    跳转首页
    :param req:
    :return:
    """
    username = req.session['username']
    total_user = User.objects.count()
    total_port = Scans.objects.count()
    date = datetime.datetime.today()
    month = date.month
    year = date.year
    # 系统的内存利用率
    free = round(psutil.virtual_memory().free / (1024.0 * 1024.0 * 1024.0), 2)
    used = round(psutil.virtual_memory().used / (1024.0 * 1024.0 * 1024.0), 2)
    psutil.cpu_count(logical=False)
    qq = get_recent_day()
    list = []
    for obj in qq:
        list.append(obj)
    list_week_day = list[::-1]
    count = []
    for i in list_week_day:
        date = str(year) + '-' + i
        end_time = str(year) + '-' + i + ' 23:59:59'
        date = datetime.datetime.strptime(date, '%Y-%m-%d')
        # end_date = datetime.datetime.strptime(end_time, '%Y-%m-%d')
        each_count = Scans.objects.filter(create_time__gte=str(date),
                                          create_time__lte=str(end_time)).count()
        count.append(each_count)
    return render(req, 'index.html', locals())


def get_recent_day():
    d = datetime.datetime.now()
    for i in range(1, 8):
        oneday = datetime.timedelta(days=i)
        day = d - oneday
        date_to = datetime.datetime(day.year, day.month, day.day)
        yield str(date_to)[5:10]


def login_out(req):
    """
    注销登录
    :param req:
    :return:
    """
    del req.session['username']
    return HttpResponseRedirect('/')


@login_request
def personal(req):
    username = req.session['username']
    role_id = req.session['role']
    user = User.objects.filter(name=username).first()
    return render(req, 'personal.html', locals())


def predict(request):
    ip = request.POST.get('ip')
    port = request.POST.get('port')
    scan = Scans.objects.filter(ip=ip, port=port).first()
    info1 = "<p>主要端口使用信息</p><p> 端口1: 3306  服务：MYSQL  漏洞：CVE-2018-2696 mysql: sha256_password 认证长密码拒绝式攻击，可能导致内存泄露、进程崩溃，从而可能实现代码执行</p> <p>端口2:8000 服务：PYTHON服务   漏洞：可能存在SQL注入风险，CSRF攻击等问题</p>"
    if scan:
        Scans.objects.create(
            ip=ip,
            port=port,
            problem=scan.problem,
            count=scan.count,
        )

        return JsonResponse({'msg': 'ok', 'result': scan.problem,'info':info1})
    os.chdir(r"D:\bysj\port_vulnerability_scanning\nikto-master\program")
    p = subprocess.Popen("Perl nikto.pl -h {} -p {}".format(ip, port), shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    content = ""
    for line in iter(p.stdout.readline, b''):
        try:
            line = line.strip().decode('utf-8')
            content += line + '\n'
        except UnicodeDecodeError as e:
            line = line.strip().decode('gbk')
            content += line + '\n'
    print(content)
    try:
        content = content.split("---------------------------------------------------------------------------")[2]
    except Exception as e:
        content = content
    content = content.replace('+', '')
    print(content)
    content = "".join(content.split('\n')[2:])
    result = translateBaidu(content)
    Scans.objects.create(
        ip=ip,
        port=port,
        problem=result,
        count=len(result),
    )
    return JsonResponse({'msg': 'ok', 'result': result, "info": info1})


def get_scans(request):
    """
    获取信息 | 模糊查询
    :param request:
    :return:
    """
    keyword = request.GET.get('name')
    page = request.GET.get("page", '')
    limit = request.GET.get("limit", '')
    response_data = {}
    response_data['code'] = 0
    response_data['msg'] = ''
    data = []
    if keyword is None:
        results_obj = Scans.objects.all()
    else:
        results_obj = Scans.objects.filter(ip__contains=keyword).all()
    paginator = Paginator(results_obj, limit)
    results = paginator.page(page)
    if results:
        for result in results:
            record = {
                "id": result.id,
                "ip": result.ip,
                "port": result.port,
                "count": result.count,
                "type": '全扫描',
                "problem": result.problem,
                'create_time': result.create_time.strftime('%Y-%m-%d %H:%m:%S'),
                "desc": result.description,
            }
            data.append(record)
        response_data['count'] = len(results_obj)
        response_data['data'] = data

    return JsonResponse(response_data)


def scans(request):
    """
    跳转用户页面
    """
    username = request.session['username']
    role = int(request.session['role'])
    user_id = request.session['user_id']
    return render(request, 'scans.html', locals())


def info(request):
    username = request.session['username']
    return render(request, 'info.html', locals())


def port_analysis(request):
    username = request.session['username']
    return render(request, 'port_analysis.html', locals())


def get_info(request):
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.datetime.fromtimestamp(boot_time_timestamp)
    start_time = "{}/{}/{} {}:{}:{}".format(bt.year, bt.month, bt.day, bt.hour, bt.minute, bt.second)
    uname = platform.uname()
    system_info = "<p>当前系统启动时间：" + start_time + "</p>" + "<p>计算机名称：" + uname.node + \
                  "</p>" + "<p>系统：" + uname.system + "</p>" + "<p>系统版本：" + uname.release + \
                  "</p>" + "<p>版本号：" + uname.version + "</p>" + "<p>系统类型：" + uname.machine + "</p>"

    cpufreq = psutil.cpu_freq()
    s_core = ""
    for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        s_core += "<p style='margin-left:1em;'>Core" + str(i) + ': ' + str(percentage) + '% ' + "</p>"
    cpu_info = "<p>处理器型号：" + str(uname.processor) + "</p>" + "<p>物理核心数：" + str(psutil.cpu_count(logical=False)) + \
               "</p>" + "<p>实际核心数：" + str(psutil.cpu_count(logical=True)) + \
               "</p>" + "<p>最高主频：" + str(cpufreq.max) + 'Mhz' + "</p>" + "<p>最低主频：" + str(cpufreq.min) + 'Mhz' + \
               "</p>" + "<p>当前频率：" + str(cpufreq.current) + 'Mhz' \
               + "</p>" + "<p>核心使用详细：" + str(s_core) + "</p>" + "<p>总体使用率：" + str(psutil.cpu_percent()) + '% ' + "</p>"
    # 系统的内存利用率 CPU
    free = str(round(psutil.virtual_memory().free / (1024.0 * 1024.0 * 1024.0), 2)) + 'GB'
    total = str(round(psutil.virtual_memory().total / (1024.0 * 1024.0 * 1024.0), 2)) + 'GB'
    memory_use_percent = str(psutil.virtual_memory().percent) + '%'
    memory_information = "<p>内存总大小：" + total + "</p>" + "<p>可用内存大小：" + free + "</p>" + "<p>内存使用率：" + memory_use_percent + "</p>"
    return JsonResponse({'system_info': system_info, 'cpu_info': cpu_info, 'memory_information': memory_information})


def get_server(request):
    os.chdir(r"D:\bysj\port_vulnerability_scanning\nikto-master\program")
    p = subprocess.Popen("Perl nikto.pl -h {} -p {}".format('127.0.0.1', '8000'), shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    content = ""
    for line in iter(p.stdout.readline, b''):
        try:
            line = line.strip().decode('utf-8')
            content += line + '\n'
        except UnicodeDecodeError as e:
            line = line.strip().decode('gbk')
            content += line + '\n'
    content = content.split("---------------------------------------------------------------------------")[2]
    content = content.replace('+', '')
    print(content)
    content = content.split('\n')[0] +content.split('\n')[1]
    print(content)
    # result = translateBaidu(content)
    return JsonResponse({"result": content})
