from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Project, Todo

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only = True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only' : True}}

    def create(self, validated_data):
        user = User(
            username = validated_data['username'],
            email = validated_data['email'],
        )
        user.set_password(validated_data['password']) 
        user.save()       
        return user 

# Serializer for JWT Token    
class TokenSerializer(serializers.Serializer):
    access_Token = serializers.CharField()
    refresh_Token = serializers.CharField()

    def validate(self, data):
        try:
            refresh = RefreshToken(data['refresh_Token'])
            access_token = refresh.access_token
            return {'access_token' : str(access_token), 'refresh_token': str(refresh)}
        except Exception as e:
            raise serializers.ValidationError('Invalid refresh token')
        

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project      
        fields = ['id', 'title', 'created_at', 'user', 'custom_id']
        read_only_fields = ['id', 'created_at', 'custom_id']  

    def validate_title(self, value):
        user = self.context['request'].user
        if Project.objects.filter(title=value, user= user).exists():
            raise serializers.ValidationError('A project with this title already exists.')
        return value
    

class TodoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Todo
        fields = ['id', 'description', 'status', 'created_at','updated_at', 'project', 'custom_id']
        read_only_fields = ['id', 'created_at', 'custom_id']

    def validate_description(self, value):
        project = self.initial_data.get('project')
        if Todo.objects.filter(description=value, project_id=project).exists():
            raise serializers.ValidationError("A todo with this description already exists in the project.")
        return value 
    

    

