from django.db import models
from django.contrib.auth.models import User
import random
import string

# Project model
class Project(models.Model):
    id = models.AutoField(primary_key=True) 
    title = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='projects')
    custom_id = models.CharField(max_length=10, unique=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.custom_id:
            last_id = Project.objects.all().order_by('id').last()
            new_id = last_id.id + 1 if last_id else 1
            self.custom_id = f"PROJ-{new_id:04d}"
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title

# Todo model
class Todo(models.Model):
    id = models.AutoField(primary_key=True) 
    description = models.TextField()
    status = models.BooleanField(default=False) 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    project = models.ForeignKey(Project, related_name='todos', on_delete=models.CASCADE)
    custom_id = models.CharField(max_length=10, unique=True, blank=True)  

    def save(self, *args, **kwargs):
        if not self.custom_id:
            last_id = Todo.objects.all().order_by('id').last()
            new_id = last_id.id + 1 if last_id else 1
            self.custom_id = f"TODO-{new_id:04d}"
        super().save(*args, **kwargs)

    def __str__(self):
        return self.description
