import datetime
import random
import string

from django.http import JsonResponse
from django.shortcuts import render, redirect

import adminPage.views
from userAuth.models import User
from django.contrib import messages

# Create your views here.


def login(request):
    if request.session.get('user_id'):
        return redirect('userPage:home')
    if request.method == 'POST':
        id = request.POST.get('idInput', '')
        pw = request.POST.get('pwInput', '')
        if User.objects.filter(id=id).exists():
            user = User.objects.get(id=id)
            if user.checkPW(pw):
                if user.isConfirmed:
                    request.session['user_id'] = user.id
                    return redirect('userPage:request')
                else:
                    messages.warning(request, "승인 요청 대기 중입니다.")
                    return redirect('userAuth:login')
            else:
                messages.error(request, "비밀번호가 일치하지 않습니다.")
                return redirect('userAuth:login')
        else:
            messages.error(request, "존재하지 않는 아이디입니다.")
            return redirect('userAuth:login')
    return render(request, 'userAuth/login.html')


def signin(request):
    if request.method=='POST':
        id = request.POST.get('id', '')
        pw = request.POST.get('pw', '')
        pwChk = request.POST.get('pwChk', '')
        dept = request.POST.get('dept', '')
        name = request.POST.get('name', '')
        phone = request.POST.get('phone', '')
        isAdmin = request.POST.get('isAdmin', '')

        if not(id and pw and pwChk and dept and name and phone and isAdmin):
            messages.error(request, "입력하지 않은 항목이 있습니다.")
            return redirect('userAuth:signin')
        elif pw != pwChk:
            messages.error(request, "비밀번호가 일치하지 않습니다.")
            return redirect('userAuth:signin')
        else:
            user = User(
                id=id,
                name=name,
                dept=dept,
                phone=phone,
                isAdmin=bool(int(isAdmin)),
            )
            user.setPW(pw)
            user.save()
            messages.success(request, "회원가입을 요청하였습니다.")
    return render(request, 'userAuth/signin.html')


def checkID(request):
    input = request.POST.get('input')
    if User.objects.filter(id=input).exists():
        result = "fail"
    else:
        result = "pass"
    context = {'result': result}
    return JsonResponse(context)


def logout(request):
    if request.session.get('user_id'):
        del(request.session['user_id'])
        messages.success(request, "정상적으로 로그아웃되었습니다.")
    return redirect('userAuth:login')


def sendCode(request):
    number = request.POST.get('number')
    code = ""
    for i in range(6):
        code += random.choice(string.digits)

    content = f"인증번호 [{code}]를 입력해 주세요."
    result = adminPage.views.sendSms(number, content)
    context = {
        'code': code,
        'result': result
    }
    return JsonResponse(context)
