from rest_framework import serializers
from account.models import User
from django.utils.encoding import*
from django.utils.http import *
from django.contrib.auth.tokens import PasswordResetTokenGenerator
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style = {'input_type': 'password'}, write_only = True)

    class Meta:
        model = User
        fields = ['email', 'name', 'tnc', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only':True}
    
        }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('passwords dont match')
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name"]
    
class UserChangePwdSerializer(serializers.ModelSerializer):
    password= serializers.CharField(max_length=255, style = {'input_type': 'password'}, write_only = True)
    password2= serializers.CharField(max_length=255, style = {'input_type': 'password'}, write_only = True)
    class Meta:
        model = User
        fields = ["password", "password2"]
    def validate(self, attrs):
        user = self.context.get('user')
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('passwords dont match')
        user.set_password(password)
        user.save()
        return attrs 
    
class UserPwdResetSerializer(serializers.ModelSerializer):
    email =serializers.EmailField(max_length =255)
    class Meta:
        model = User
        fields= ['email']
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user= User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link= 'http://localhost:3000/api/user/reset/'+uid+'/'+token
            print('link', link)
            return attrs
        else:
            raise serializers.ValidationError('email not registered')
        
class UserPwdReset2Serializer(serializers.ModelSerializer):
    password= serializers.CharField(max_length=255, style = {'input_type': 'password'}, write_only = True)
    password2= serializers.CharField(max_length=255, style = {'input_type': 'password'}, write_only = True)
    class Meta:
        model = User
        fields = ["password", "password2"]
    def validate(self, attrs):
        password = attrs.get('password')
        password2= attrs.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')
        if password != password2:
            raise serializers.ValidationError('passwords dont match')
        id = smart_str(urlsafe_base64_decode(uid))
        user= User.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user,token):
            raise serializers.ValidationError('link not correct token')
        user.set_password(password)
        user.save()
        return attrs 