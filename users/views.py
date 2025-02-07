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
from django.http import JsonResponse
import json

User = get_user_model()

# تابع کمکی برای ارسال پیام خطا
def send_error(message, status_code=status.HTTP_400_BAD_REQUEST):
    return JsonResponse({"msg": message}, status=status_code)

# ✅ نمایش صفحه ثبت‌نام
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
        user.set_password(password)
        user.save()

        messages.success(request, "ثبت‌نام با موفقیت انجام شد، لطفاً وارد شوید.")
        return redirect("login_page")

class LoginPageView(View):
    def get(self, request):
        return render(request, "login.html")

    def post(self, request):
        try:
            data = json.loads(request.body)  # دریافت داده‌های JSON
            username = data.get("username")
            password = data.get("password")

            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)

                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                response = JsonResponse({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "msg": "ورود موفقیت‌آمیز بود!",
                })
                
                # ذخیره توکن در کوکی برای امنیت بهتر
                response.set_cookie("access_token", access_token, httponly=True, samesite='Lax')
                response.set_cookie("refresh_token", refresh_token, httponly=True, samesite='Lax')

                return response
            
            return JsonResponse({"msg": "نام کاربری یا رمز عبور اشتباه است."}, status=401)

        except json.JSONDecodeError:
            return JsonResponse({"msg": "درخواست نامعتبر است."}, status=400)


# ✅ نمایش صفحه اصلی
class HomePageView(View):
    def get(self, request):
        if not request.user.is_authenticated:
            return redirect("login_page")

        return render(request, "home.html", {"username": request.user.username})

# ✅ خروج از حساب و حذف توکن از session
class LogoutView(View):
    def get(self, request):
        logout(request)

        # حذف توکن از session
        request.session.pop('access_token', None)
        request.session.pop('refresh_token', None)

        messages.success(request, "شما با موفقیت خارج شدید.")
        return redirect('login_page')

# ✅ API ثبت‌نام
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg": "کاربر با موفقیت ثبت شد."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# ✅ API لاگین و دریافت توکن JWT
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
                "role": user.role,
            }, status=status.HTTP_200_OK)

        return send_error("نام کاربری یا رمز عبور اشتباه است.", status.HTTP_401_UNAUTHORIZED)

# ✅ API صفحه محافظت‌شده
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"msg": f"دسترسی به منابع محافظت‌شده برای {request.user.username} تایید شد!"}, status=status.HTTP_200_OK)

# ✅ API صفحه اصلی
class HomePageApiView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({"msg": f"سلام {user.username}, خوش آمدید!"}, status=status.HTTP_200_OK)

# ✅ API نمایش لاگ‌ها
class LogListView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        with open("logs/gateway.log", "r") as log_file:
            logs = log_file.readlines()[-50:]
        return Response({"logs": logs})


