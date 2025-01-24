from rest_framework import serializers
from .models import User  # اینجا باید از مدل سفارشی خودت استفاده کنی

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'email', 'role']  # فیلد role را اضافه کن
        extra_kwargs = {'password': {'write_only': True}}  # رمز عبور را فقط نوشتنی کن

    def create(self, validated_data):
        password = validated_data.pop('password')  # رمز عبور را جدا کن
        user = User(**validated_data)  # کاربر را بساز
        user.set_password(password)  # رمز عبور را هش کن
        user.save()
        return user


