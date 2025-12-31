from django.urls import path
from . import views

urlpatterns = [
    path('', views.logins, name='logins'),
    path('register/', views.register, name='register'),
    path('main/', views.main, name='main'),
    path('main/members/', views.members, name='members'),
    path('main/members/add/', views.add_member, name='add_member'),
    path('main/members/details/<int:id>/', views.details, name='details'),
    path('main/members/<int:id>/promote/head/', views.confirm_promote_head, name='confirm_promote_head'),
    path('testing/', views.testing, name='testing'),
    path('main/members/<int:id>/promote/secretariat/', views.confirm_promote_secretariat, name='confirm_promote_secretariat'),
    path('main/members/<int:id>/edit/', views.edit_member, name='edit_member'),
    path('main/members/<int:id>/demote-head/', views.confirm_demote_head, name='confirm_demote_head'),
    path('main/members/<int:id>/demote-secretariat/', views.confirm_demote_secretariat, name='confirm_demote_secretariat'),
    path('main/members/<int:id>/delete', views.confirm_delete_member, name='confirm_delete_member'),
    path('main/members/search/', views.member_search_api, name='member_search_api'),
    path('logout/', views.logout, name='logout')
]