from django.shortcuts import render
from django.http import HttpResponse
from django.views.generic import TemplateView
# Create your views here.
class HomeView(TemplateView):
    template_name = 'home.html'

class QuizView(TemplateView):
    template_name = 'quiz.html'

class LeaderboardView(TemplateView):
    template_name = 'leaderboard.html'

class BlogView(TemplateView):
    template_name = 'blog.html'

class AllQuizView(TemplateView):
    template_name = 'all_quiz.html'

class AboutView(TemplateView):
    template_name = 'about.html'

