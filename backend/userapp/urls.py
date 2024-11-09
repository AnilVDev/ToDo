from django.urls import path
from .views import *

urlpatterns = [
    # path('hello/', HelloWorldView.as_view(), name='hello-world'),
    path('signup/', UserSignUpView.as_view(), name='user-signup'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('projects/', ProjectCreateListView.as_view(), name='project-list-create'),
    path('projects/<int:pk>/', ProjectDetailView.as_view(), name='project-detail'),
    path('projects/<int:project_id>/todos/', TodoCreateListView.as_view(), name='todo-list-create'),
    path('projects/<int:project_id>/todos/<int:pk>/', TodoDetailView.as_view(), name='todo-detail'),
]