from django.urls import path
from . import views

app_name = 'adminPage'
urlpatterns = [
    path('admin/', views.admin, name='admin'),
    path('admin/product/', views.productMng, name='productMng'),
    path('admin/product/append', views.productAppend, name='productAppend'),
    path('admin/product/<str:productId>', views.productDetail, name='productDetail'),
    path('admin/request/', views.requestMng, name='requestMng'),
    path('admin/user/', views.userMng, name='userMng'),
    path('admin/user/append', views.userAppend, name='userAppend'),
    path('admin/user/<str:currentUserId>/', views.userDetail, name='userDetail'),
    path('admin/user/<str:currentUserId>/delete/', views.userDetailDelete, name='userDetailDelete'),
    path('admin/account/', views.account, name='account'),
]
