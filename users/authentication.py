from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils.timezone import now
import logging

logger = logging.getLogger("gateway_logger")

class GatewayJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        user_auth_tuple = super().authenticate(request)
        if user_auth_tuple is None:
            return None
        
        user, token = user_auth_tuple

        # گرفتن اطلاعات لاگین و ثبت در لاگ
        ip = self.get_client_ip(request)
        request_time = now()

        logger.info(f"[{request_time}] Authenticated User: {user.username}, IP: {ip}")

        return user, token

    def get_client_ip(self, request):
        """ گرفتن آی‌پی کلاینت """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
