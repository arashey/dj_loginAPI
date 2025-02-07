from django.urls import path
from .views import RegisterPageView, LoginPageView, HomePageView, RegisterView, LoginView, ProtectedView, LogoutView, HomePageApiView, LogListView

urlpatterns = [
    # صفحات HTML
    path("register/", RegisterPageView.as_view(), name="register_page"),
    path("login/", LoginPageView.as_view(), name="login_page"),
    path("home/", HomePageView.as_view(), name="home_page"),
    path('logout/', LogoutView.as_view(), name='logout_page'),

    # API ها
    path("api/register/", RegisterView.as_view(), name="register_api"),  # ثبت‌نام
    path("api/login/", LoginView.as_view(), name="login_api"),  # ورود
    path("api/protected/", ProtectedView.as_view(), name="protected_api"),  # صفحه محافظت‌شده
    path("api/logout/", LogoutView.as_view(), name="logout_api"), 
     path("api/home/", HomePageApiView.as_view(), name="home_api"),  # خروج از سیستم
  path('api/logs/', LogListView.as_view(), name='log_list'),
]




