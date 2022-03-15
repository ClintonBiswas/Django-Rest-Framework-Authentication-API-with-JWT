
from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from account.utils import Util

# Registration Serializer
class UserRegistationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'},write_only=True)
    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'password2', 'tc']
        extra_kwargs = {
            'password':{'write_only': True}
        }
    # Validate for password and confirm passwaord while registration

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            raise serializers.ValidationError("Password and confirm Password doesn't matched.")
        return attrs
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

# Login Serializer
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']

# User Profile Get Data
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email']

# Change Password Serializer
class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'},write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'},write_only=True)
    class Meta:
        fields = ['password', 'password2']
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')

        if password != password2:
            raise serializers.ValidationError('Password and Confirm password not match!')
        user.set_password(password)
        user.save()
        return attrs

# Reset Passwors Serializer

class UserResetPassworsSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('User Id: ', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token: ', token)
            link = 'http//localhost:3000/api/user/reset/'+uid+'/'+token
            print('Password Reset Link: ', link)
            # Send Email
            body = 'Click Following Link To Reset Your Password ' + link
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email':user.email

            }
            Util.send_email(data)
            return attrs
        else:
            return serializers.ValidationError("Your Email Is Not Registered")

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        fields = ['password', 'password2']
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')