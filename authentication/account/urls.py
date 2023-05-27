from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from django.urls import path,include
from .views import *

urlpatterns = [
    
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', UserRegistrationView.as_view(), name='registration'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepwd/', UserChangePwdView.as_view(), name='changepwd'),
    path('pwdreset/', UserPwdResetView.as_view(), name='pwdreset'),
    path('pwdreset/<uid>/<token>/', UserPwdReset2View.as_view(), name='pwdreset2'),


]