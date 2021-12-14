from django.urls import path
from . import views

app_name = 'userPage'
urlpatterns = [
    path('home/', views.home, name='home'),
    path('account/', views.account, name='account'),
    path('withdraw/', views.withdraw, name='withdraw'),
    path('request/', views.request, name='request'),
    path('request/<str:productId>', views.requestDetail, name='requestDetail'),
    path('history/', views.history, name='history'),

]