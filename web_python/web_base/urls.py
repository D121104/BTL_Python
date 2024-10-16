from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('quiz/', views.quiz, name='quiz'),
    path('leaderboard/', views.leaderboard, name='leaderboard'),
    path('blog/', views.blog, name='blog'),
    path('all_quiz/', views.all_quiz, name='all_quiz'),
    path('about/', views.about_, name='about_'),

]