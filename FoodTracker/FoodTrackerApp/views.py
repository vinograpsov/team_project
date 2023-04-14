from django.shortcuts import render

from django.http import HttpResponse
from .models import User, Product


def index(request):
    return HttpResponse("hello test django")



def user_list(request):
    users = User.objects.all()
    return render(request, 'user_list.html', {'users': users})


def product_list(request):
    products = Product.objects.all()
    return render(request, 'products_list.html',{'products' : products})