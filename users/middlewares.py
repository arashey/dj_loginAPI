import logging
from django.utils.timezone import now

logger = logging.getLogger("gateway_logger")

class GatewayLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # گرفتن اطلاعات کاربر و درخواست
        user = request.user if request.user.is_authenticated else "Anonymous"
        ip = self.get_client_ip(request)
        request_size = len(request.body)  # حجم داده‌های ارسال شده
        request_time = now()

        # استخراج توکن از هدر درخواست
        token = self.get_token_from_request(request)

        # لاگ کردن اطلاعات
        logger.info(f"[{request_time}] User: {user}, IP: {ip}, Request Size: {request_size} bytes, Token: {token}, Path: {request.path}")

        # ادامه پردازش درخواست
        response = self.get_response(request)

        return response

    def get_client_ip(self, request):
        """ گرفتن آی‌پی کلاینت """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get_token_from_request(self, request):
        """ دریافت توکن از هدر درخواست """
        auth_header = request.headers.get("Authorization")
        print("Auth Header Received:", auth_header)  # لاگ برای بررسی هدر
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header.split(" ")[1]  # جدا کردن توکن از "Bearer "
        return "No Token"




