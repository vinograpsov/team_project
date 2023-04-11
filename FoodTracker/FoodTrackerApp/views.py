from django.shortcuts import render

from django.http import HttpResponse
from .models import User


def index(request):
    return HttpResponse("hello test django")



def user_list(request):
    users = User.objects.all()
    return render(request, 'user_list.html', {'users': users})