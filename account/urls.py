from django.urls import path
from account import views

app_name = 'account'

urlpatterns = [
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('change_password/', views.UserChangePasswordView.as_view(), name='change_password'),
    path('send-reset-password/', views.UserRestPasswordView.as_view(), name='send-reset-password'),
   # path('reset-password/<uid>/<token>/', views.UserResetPassEmailView.as_view(), name='pass-reset'),
    path('reset-password/<uid>/<token>/', views.UserPasswordResetView.as_view(), name='reset-password'),
    
]
