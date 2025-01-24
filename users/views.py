from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.views import View
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from .serializers import UserSerializer
from .permissions import IsAdminUser
from django.contrib import messages

User = get_user_model()

# تابع کمکی برای ارسال پیام خطا
def send_error(message, status_code=status.HTTP_400_BAD_REQUEST):
    return JsonResponse({"msg": message}, status=status_code)

# نمایش صفحه ثبت‌نام
class RegisterPageView(View):
    def get(self, request):
        return render(request, "register.html")

    def post(self, request):
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            return render(request, "register.html", {"error": "نام کاربری و رمز عبور الزامی است."})

        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {"error": "نام کاربری قبلاً استفاده شده است."})

        user = User(username=username)
        user.set_password(password)  # هش کردن رمز عبور
        user.save()
        return redirect("login_page")


# نمایش صفحه لاگین
class LoginPageView(View):
    def get(self, request):
        return render(request, "login.html")

    def post(self, request):
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            messages.error(request, "نام کاربری و رمز عبور الزامی است.")
            return redirect('login_page')  # یا همان صفحه ورود

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect("home_page")

        messages.error(request, "نام کاربری یا رمز عبور اشتباه است.")
        return redirect('login_page')


# نمایش صفحه اصلی (فقط کاربران لاگین شده)
class HomePageView(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return redirect("login_page")
        return render(request, "home.html", {"username": request.user.username})
    

class LogoutView(View):
    def get(self, request):
        # خروج از سیستم
        logout(request)
        # هدایت به صفحه ثبت‌نام بعد از خروج
        return redirect('register_page')  # یا نام URL صفحه ثبت‌نام شما



# ✅ API ثبت‌نام با استفاده از UserSerializer
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg": "کاربر با موفقیت ثبت شد."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ✅ API ورود کاربر و دریافت توکن JWT + بررسی نقش
class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return send_error("نام کاربری یا رمز عبور الزامی است.", status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "role": user.role,  # ارسال نقش کاربر در پاسخ
            }, status=status.HTTP_200_OK)

        return send_error("نام کاربری یا رمز عبور اشتباه است.", status.HTTP_401_UNAUTHORIZED)


# ✅ API صفحه محافظت‌شده (فقط برای ادمین‌ها)
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]  # استفاده از IsAdminUser

    def get(self, request):
        return Response({"msg": f"دسترسی به منابع محافظت‌شده برای {request.user.username} تایید شد!"}, status=status.HTTP_200_OK)


# ✅ API صفحه اصلی برای کاربران احراز هویت شده
class HomePageApiView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({"msg": f"سلام {user.username}, خوش آمدید!"}, status=status.HTTP_200_OK)


# ✅ API خروج از سیستم با بررسی اعتبار توکن
'''class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return send_error("توکن معتبر نیست.", status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()  # بی‌اعتبار کردن توکن
            return Response({"msg": "خروج از سیستم با موفقیت انجام شد."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return send_error("توکن نامعتبر است.", status.HTTP_400_BAD_REQUEST)'''










