from django.urls import path
from . import views

app_name = 'userAuth'
urlpatterns = [
    path('', views.login, name='login'),
    path('signin/', views.signin, name='signin'),
    path('signin/checkID/', views.checkID, name='checkID'),
    path('signin/sendCode/', views.sendCode, name='sendCode'),
    path('logout/', views.logout, name='logout')
]