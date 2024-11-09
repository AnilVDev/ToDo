from django.contrib import admin
from .models import Project, Todo
# Register your models here.
from django.contrib.auth.models import User

class CustomUserAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'username',
        'email',
        'date_joined',
    )

# Unregister the default User admin and register the custom one
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)


class adminProject(admin.ModelAdmin):
    list_display = (
        'id',
        'title',
        'created_at',
        'user',
        'custom_id',
    )

admin.site.register(Project,adminProject)

class adminTodo(admin.ModelAdmin):
    list_display = (
        'id',
        'description',
        'status',
        'created_at',
        'updated_at',
        'project',
        'custom_id',
    )

admin.site.register(Todo,adminTodo)