import base64
import hashlib
import hmac
import json
import time
import requests
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from comprod.settings import get_secret
from userAuth.models import User
from userPage.models import Product, Ledger


def sendSms(number, text):
    service_id = get_secret("service_id")
    url = f"https://sens.apigw.ntruss.com/sms/v2/services/{service_id}/messages"
    timestamp = str(int(time.time() * 1000))
    secret_key = bytes(get_secret('auth_secret_key'), 'utf-8')
    method = 'POST'
    uri = f'/sms/v2/services/{service_id}/messages'
    message = bytes(f'{method} {uri}\n{timestamp}\n{get_secret("access_key_id")}', 'utf-8')
    signing_key = base64.b64encode(hmac.new(secret_key, message, digestmod=hashlib.sha256).digest())
    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'x-ncp-apigw-timestamp': timestamp,
        'x-ncp-iam-access-key': get_secret('access_key_id'),
        'x-ncp-apigw-signature-v2': signing_key,
    }
    body = {
        'type': 'SMS',
        'contentType': 'COMM',
        'countryCode': '82',
        'from': f'{get_secret("send_number")}',
        'content': f'{text}',
        'messages': [
            {
                'to': f'{number}'
            }
        ]
    }
    encoded_data = json.dumps(body)
    res = requests.post(url, headers=headers, data=encoded_data)
    return res.status_code


def admin(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')
    return render(request, 'adminPage/admin.html', {'user': user, 'current': "admin"})


def productMng(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')
    return render(request, 'adminPage/productMng.html', {
        'user': user,
        'current': "productMng",
        'products': Product.objects.all().order_by('id'),
        'cls': Product.objects.raw('SELECT distinct cls FROM userPage_product'),
    })


def productDetail(request, productId):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')
    currentProduct = get_object_or_404(Product, id=productId)
    return render(request, 'adminPage/productDetail.html', {
        'user': user,
        'current': "productMng",
        'currentProduct': currentProduct,
    })


def productDelete(request, productId):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')

    product = User.objects.get(id=productId)
    messages.success(request, product.name + "물품을 삭제했습니다.")
    product.delete()
    return redirect('adminPage:userMng')



def productAppend(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')
    if request.method == 'POST':
        name = request.POST.get('name')
        cls = request.POST.get('cls')
        stock = request.POST.get('stock')
        image = request.POST.get('image')

        if image is None:
            if not (name and cls and stock):
                messages.error(request, "모든 항목을 빠짐없이 입력 해주세요.")
                return redirect('adminPage:productAppend')
        elif not (name and cls and stock and image):
            messages.error(request, "모든 항목을 빠짐없이 입력 해주세요.")
            return redirect('adminPage:productAppend')

        stock = int(stock)
        image = request.FILES["image"]

        product = Product(
            name=name,
            cls=cls,
            stock=stock,
            image=image,
        )
        product.save()
        messages.success(request, name + " 품목을 추가하였습니다.")
        return redirect('adminPage:productMng')
    return render(request, 'adminPage/productAppend.html', {
        'user': user,
        'current': "productMng",
    })

def requestMng(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')

    sql = "select l.id as id, u.name as userName, l.who as userId, p.name as prodName, l.what as prodId, whenn, quantity * -1 as quantity, stock, a.name as adminName, l.confirmedBy as adminId from userAuth_user as u join userPage_ledger as l on (u.id=l.who) left join userAuth_user as a on (l.confirmedBy=a.id) join userPage_product as p on (l.what = p.id)"

    if request.method == 'POST':
        ledgerId = request.POST.get('ledgerId')
        ledger = get_object_or_404(Ledger, id=ledgerId)
        product = get_object_or_404(Product, id=ledger.what)
        remain = product.inout(ledger.quantity)
        ledger.confirmedBy = user.id
        who = get_object_or_404(User, id=ledger.who)
        isApprove = request.POST.get('isApprove')
        if isApprove == "true":
            product.save()
            ledger.save()
            sms = f"{who.name}님이 요청하신 {product.name} 품목 {-ledger.quantity}개 승인되었습니다."
            result = sendSms(who.phone, sms)
            if result == 202:
                messages.success(request, "요청을 승인했습니다. " + product.name + " 품목의 재고수량 : " + str(remain))
            else:
                messages.warning(request, f"요청을 승인하였으나 SMS 발송에 실패하였습니다. ({result})" + product.name + " 품목의 재고수량 : " + str(remain))
        elif isApprove == "false":
            ledger.delete()
            sms = f"{who.name}님이 요청하신 {product.name} 품목 {-ledger.quantity}개 거절되었습니다."
            result = sendSms(who.phone, sms)
            if result == 202:
                messages.success(request, "요청을 거절했습니다. " + product.name + " 품목의 재고수량 : " + str(product.stock))
            else:
                messages.warning(request, f"요청을 거절하였으나 SMS 발송에 실패하였습니다. ({result})" + product.name + " 품목의 재고수량 : " + str(product.stock))
        return redirect('adminPage:requestMng')
    return render(request, 'adminPage/requestMng.html', {
        'user': user, 'current': "requestMng", 'ledger': Ledger.objects.raw(sql)
    })


def userMng(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')

    return render(request, 'adminPage/userMng.html', {
        'user': user,
        'current': "userMng",
        'users': User.objects.all().order_by('joinDate'),
    })


def account(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')

    if request.method == 'POST':
        pw = request.POST.get('currentPW')
        newPw = request.POST.get('newPW')
        chkPw = request.POST.get('chkPW')
        name = request.POST.get('name')
        dept = request.POST.get('dept')
        phone = request.POST.get('phone')
        changed = ""
        if not pw:
            messages.error(request, "현재 비밀번호를 입력해주세요.")
            return redirect('adminPage:account')
        elif not user.checkPW(pw):
            messages.error(request, "현재 비밀번호가 일치하지 않습니다.")
            return redirect('adminPage:account')
        else:
            if newPw or chkPw or name or dept or phone:
                if newPw or chkPw:
                    if newPw == chkPw:
                        user.setPW(newPw)
                        changed += " 비밀번호"
                    else:
                        messages.error(request, "새 비밀번호가 일치하지 않습니다.")
                        return redirect('adminPage:account')
                if name:
                    user.name = name
                    changed += " 이름"
                if dept:
                    user.dept = dept
                    changed += " 부서"
                if phone:
                    user.phone = phone
                    changed += " 전화번호"
                user.save()
                messages.success(request, "변경된 항목 :" + changed)
                return redirect('adminPage:account')
            else:
                messages.warning(request, "변경된 항목이 없습니다.")
                return redirect('adminPage:account')
    return render(request, 'adminPage/account.html', {'user': user, 'current': "account"})


def userDetail(request, currentUserId):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')

    currentUser = get_object_or_404(User, id=currentUserId)

    if request.method == 'POST':
        isChanged = False
        changed = ""
        id = request.POST.get('id')
        isConfirmed = request.POST.get('isConfirmed')
        isAdmin = request.POST.get('isAdmin')
        newPW = request.POST.get('newPW')
        chkPW = request.POST.get('chkPW')
        name = request.POST.get('name')
        dept = request.POST.get('dept')
        phone = request.POST.get('phone')

        if currentUser.isAdmin:
            if isAdmin != "True":
                currentUser.isAdmin = False
                isChanged = True
                changed += " 사용자 유형"
        else:
            if isAdmin == "True":
                currentUser.isAdmin = True
                isChanged = True
                changed += " 사용자 유형"

        if currentUser.isConfirmed:
            if isConfirmed != "True":
                currentUser.isConfirmed = False
                isChanged = True
                changed += " 승인여부"
        else:
            if isConfirmed == "True":
                currentUser.isConfirmed = True
                isChanged = True
                changed += " 승인여부"

        if newPW or chkPW:
            if newPW == chkPW:
                currentUser.setPW(newPW)
                isChanged = True
                changed += " 비밀번호"
            else:
                messages.error(request, "비밀번호가 일치하지 않습니다.")
                return redirect('adminPage:userDetail', currentUser.id)
        if name:
            if currentUser.name != name:
                currentUser.name = name
                isChanged = True
                changed += " 이름"
        if dept:
            if currentUser.dept != dept:
                currentUser.dept = dept
                isChanged = True
                changed += " 부서"
        if phone:
            if currentUser.phone != phone:
                currentUser.phone = phone
                isChanged = True
                changed += " 연락처"
        if isChanged:
            currentUser.save()
            messages.success(request, "변경된 내용 :" + changed)
            return redirect('adminPage:userDetail', currentUser.id)
        else:
            messages.warning(request, "변경된 내용이 없습니다.")
            return redirect('adminPage:userDetail', currentUser.id)
    return render(request, 'adminPage/userDetail.html', {
        'user': user,
        'current': "userMng",
        'currentUser': currentUser,
    })


def userDetailDelete(request, currentUserId):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')
    if user.id == currentUserId:
        messages.error(request, "현재 접속중인 계정입니다. 삭제할 수 없습니다.")
        return redirect('adminPage:userDetail', currentUserId)
    else:
        currentUser = User.objects.get(id=currentUserId)
        messages.success(request, currentUser.name + "(" + currentUser.id + ")님의 계정을 삭제했습니다.")
        currentUser.delete()
    return redirect('adminPage:userMng')


def userAppend(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
        if not user.isAdmin:
            messages.error(request, "관리자만 접근할 수 있습니다.")
            return redirect('/')
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')

    if request.method == 'POST':
        id = request.POST.get('id')
        isConfirmed = request.POST.get('isConfirmed')
        isAdmin = request.POST.get('isAdmin')
        newPW = request.POST.get('newPW')
        chkPW = request.POST.get('chkPW')
        name = request.POST.get('name')
        dept = request.POST.get('dept')
        phone = request.POST.get('phone')

        if not (id and newPW and chkPW and name and dept and phone):
            messages.error(request, "모든 항목을 빠짐없이 입력 해주세요.")
            return redirect('adminPage:userAppend')
        elif newPW != chkPW:
            messages.error(request, "비밀번호가 일치하지 않습니다.")
            return redirect('adminPage:userAppend')
        else:
            newUser = User(
                id=id,
                name=name,
                dept=dept,
                phone=phone,
            )
            newUser.setPW(newPW)
            if isConfirmed == "True":
                newUser.isConfirmed = True
            if isAdmin == "True":
                newUser.isAdmin = True
            else:
                newUser.isAdmin = False
            newUser.save()
            messages.success(request, name + "(" + id + ")님의 계정이 생성되었습니다.")
            return redirect('adminPage:userMng')
    return render(request, 'adminPage/userAppend.html', {
        'user': user,
        'current': "userMng"
    })
