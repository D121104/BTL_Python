from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.
def home(request):
    return render(request, 'home.html')

def quiz(request):
    return render(request, 'quiz.html')

def leaderboard(request):
    return render(request, 'leaderboard.html')

def blog(request):
    return render(request, 'blog.html')

def all_quiz(request):
    return render(request, 'all_quiz.html')

def about_(request):
    return render(request, 'about.html')
