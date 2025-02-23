from django.contrib import admin
from django.urls import path, include  # Include is needed!
from .views import home

urlpatterns = [
    path("", home),
    path('admin/', admin.site.urls),
    path('api/', include('influencers.urls')),  # This includes API routes correctly
]
