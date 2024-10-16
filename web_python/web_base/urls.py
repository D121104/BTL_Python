from django.urls import path
from .views import HomeView, QuizView, LeaderboardView, BlogView, AllQuizView, AboutView

urlpatterns = [
    path('', HomeView.as_view(), name='home'),
    path('quiz/', QuizView.as_view(), name='quiz'),
    path('leaderboard/', LeaderboardView.as_view(), name='leaderboard'),
    path('blog/', BlogView.as_view(), name='blog'),
    path('all_quiz/', AllQuizView.as_view(), name='all_quiz'),
    path('about/', AboutView.as_view(), name='about'),
]