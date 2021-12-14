import datetime

from userAuth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
# Create your views here.
from userPage.models import Product, Ledger


def home(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')
    return render(request, 'userPage/home.html', {'user': user, 'current': "home"})


def account(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
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
            return redirect('userPage:account')
        elif not user.checkPW(pw):
            messages.error(request, "현재 비밀번호가 일치하지 않습니다.")
            return redirect('userPage:account')
        else:
            if newPw or chkPw or name or dept or phone:
                if newPw or chkPw:
                    if newPw == chkPw:
                        user.setPW(newPw)
                        changed += " 비밀번호"
                    else:
                        messages.error(request, "새 비밀번호가 일치하지 않습니다.")
                        return redirect('userPage:account')
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
                return redirect('userPage:account')
            else:
                messages.warning(request, "변경된 항목이 없습니다.")
                return redirect('userPage:account')
    return render(request, 'userPage/account.html', {'user': user, 'current': "account"})


def request(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')
    if request.method == 'POST':
        cls = request.POST.get('filter')
        search = request.POST.get('search')
        if search:
            if cls == "all":
                return render(request, 'userPage/request.html', {
                    'user': user,
                    'current': "request",
                    'products': Product.objects.all().filter(name__icontains=search).order_by('id'),
                    'cls': Product.objects.values_list('cls', flat=True).distinct(),
                    'filterSelected': cls
                })
            return render(request, 'userPage/request.html', {
                'user': user,
                'current': "request",
                'products': Product.objects.all().filter(cls=cls, name__icontains=search).order_by('id'),
                'cls': Product.objects.values_list('cls', flat=True).distinct(),
                'filterSelected': cls
            })
        else:
            if cls == "all":
                return render(request, 'userPage/request.html', {
                    'user': user,
                    'current': "request",
                    'products': Product.objects.all().order_by('id'),
                    'cls': Product.objects.values_list('cls', flat=True).distinct(),
                    'filterSelected': cls
                })
            return render(request, 'userPage/request.html', {
                'user': user,
                'current': "request",
                'products': Product.objects.all().filter(cls=cls).order_by('id'),
                'cls': Product.objects.values_list('cls', flat=True).distinct(),
                'filterSelected': cls
            })
    return render(request, 'userPage/request.html', {
        'user': user,
        'current': "request",
        'products': Product.objects.all().order_by('id'),
        'cls': Product.objects.values_list('cls', flat=True).distinct(),
        'filterSelected': "all"
    })


def requestDetail(request, productId):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')
    product = get_object_or_404(Product, id=productId)
    if request.method == 'POST':
        quantity = int(request.POST.get('quantity'))
        if quantity > product.stock:
            messages.error(request, "재고 수량이 부족합니다.")
            return redirect('userPage:requestDetail', productId)
        newRequest = Ledger(
            who=user.id,
            what=product.id,
            quantity=-quantity,
        )
        newRequest.save()
        messages.success(request, "물품 요청이 접수되었습니다.")
        return redirect('userPage:request')
    return render(request, 'userPage/requestDetail.html', {
        'user': user,
        'current': "request",
        'product': product,
    })


def history(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')

    sql = "select userPage_ledger.id, userPage_product.name, whenn, quantity*-1 as quantity, userAuth_user.id as confId, userAuth_user.name as confName " \
          + "from userPage_product join userPage_ledger on (userPage_product.id = userPage_ledger.what) left join userAuth_user on (confirmedBy = userAuth_user.id) " \
          + "where who=\'" \
          + user.id + "\' " \
          + "order by whenn desc"

    if request.method == 'POST':
        ledgerId = request.POST.get('ledgerId')
        ledger = get_object_or_404(Ledger, id=ledgerId)
        ledger.delete()
        messages.success(request, "요청이 삭제되었습니다.")
        return redirect('userPage:history')

    return render(request, 'userPage/history.html', {
        'user': user, 'current': "history", 'ledger': Ledger.objects.raw(sql)
    })


def withdraw(request):
    user_id = request.session.get('user_id')
    if user_id:
        user = User.objects.get(id=user_id)
    else:
        messages.error(request, "로그인 후 이용하실 수 있습니다.")
        return redirect('/')

    if request.method == 'POST':
        pw = request.POST.get('pw')
        if pw:
            if user.checkPW(pw):
                user.delete()
                del (request.session['user_id'])
                messages.success(request, user_id + " 계정이 삭제되었습니다.")
                return redirect('userAuth:login')
            else:
                messages.error(request, "비밀번호가 일치하지 않습니다.")
                return redirect('userPage:withdraw')
        else:
            messages.error(request, "비밀번호를 입력해주세요.")
            return redirect('userPage:withdraw')

    return render(request, 'userPage/withdraw.html', {'user': user, 'current': "withdraw"})
