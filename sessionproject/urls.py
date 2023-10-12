from django.contrib import admin
from django.urls import path,include
from sessionapp import urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include('sessionapp.urls')),
]
