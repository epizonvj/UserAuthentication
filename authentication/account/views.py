from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    def post(self,request,format=None):
        data= request.data
        serializer = UserRegistrationSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'msg': 'registration succesful', 'token': token})
        return Response(serializer.errors)
    
class UserLoginView(APIView):
    def post(self,request,format=None):
        data= request.data
        serializer = UserLoginSerializer(data=data)
        if serializer.is_valid():
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is None:
                return Response({'msg': 'user doesnt exist'})
            else:
                token = get_tokens_for_user(user)

                return Response({'msg': 'login succesful', 'token': token})
        return Response(serializer.errors)
    

class UserProfileView(APIView):
    permission_classes= [IsAuthenticated]
    def get(self,request,format=None):
        serializer= UserProfileSerializer(request.user)
        return Response (serializer.data)
    

class UserChangePwdView(APIView):
    permission_classes= [IsAuthenticated]
    def post(self,request,format=None):
        data= request.data
        serializer = UserChangePwdSerializer(data=data,context = {'user': request.user})
        if serializer.is_valid():
            return Response ({'msg': 'password changed'})
            user = authenticate(email=email, password=password)
        return Response(serializer.errors)


class UserPwdResetView(APIView):
    
    def post(self,request,format=None):
        data= request.data
        serializer = UserPwdResetSerializer(data=data)
        if serializer.is_valid():
            return Response ({'msg': 'email sent'})
            user = authenticate(email=email, password=password)
        return Response(serializer.errors)

class UserPwdReset2View(APIView):
    
    def post(self,request,uid, token,format=None):
        data= request.data 
        serializer = UserPwdReset2Serializer(data=data, context = {'uid':uid, 'token': token})
        if serializer.is_valid():
            return Response({'msg': 'reset using link'})
        return Response(serializer.errors)