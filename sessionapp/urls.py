from django.urls import path
from .views import Register,LogOut,UserLogin

urlpatterns = [
    # Your other URL entries.
    path('register/', Register.as_view(), name='register'),
    path('login/',UserLogin.as_view(), name='login'),
    path('logout/',LogOut.as_view(), name='logout'),
]