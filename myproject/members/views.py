from django.http import HttpResponse, JsonResponse
from django.template import loader
from django.shortcuts import render, redirect, get_object_or_404
from django.core.exceptions import ValidationError
from django.contrib import messages
# from django.contrib.auth import login, authenticate
# from django.contrib.auth.forms import AuthenticationForm
# from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.db.models import Q
from .models import Member, Department, Role
from .utils import get_current_user, can_manage_members, can_delete_member
import traceback
import re

def members(request):
    current_user = get_current_user(request)
    query = request.GET.get('q', '').strip()

    mymembers = Member.objects.all()

    if query:
        terms = query.split()
        q_obj = Q()

        for term in terms:
            q_obj &= (
                Q(firstname__icontains=term) |
                Q(lastname__icontains=term)
            )

        mymembers = mymembers.filter(q_obj)

    context = {
        'mymembers': mymembers,
        'current_user': current_user,
        'query': query,
    }
    return render(request, 'all_members.html', context)

def details(request, id):
    mymember = get_object_or_404(Member, id=id)
    current_user = get_current_user(request)
    departments = Department.objects.all()

    context = {
        'mymember': mymember,
        'departments': departments,
        'current_user' : current_user,
    }
    return render(request, 'details.html', context)

def main(request):
    current_user = get_current_user(request)
    return render(request, 'main.html', {
        'current_user': current_user
    })

def member_search_api(request):
    query = request.GET.get('q', '').strip()

    members = Member.objects.none()

    if query:
        parts = query.split()

        if len(parts) == 1:
            members = Member.objects.filter(
                Q(firstname__icontains=parts[0]) |
                Q(lastname__icontains=parts[0])
            )
        else:
            members = Member.objects.filter(
                Q(firstname__icontains=parts[0]) &
                Q(lastname__icontains=parts[-1])
            )

    data = [
        {
            "id": m.id,
            "name": f"{m.firstname} {m.lastname}",
            "role": str(m.role),
            "photo": m.profile_photo.url if m.profile_photo else None
        }
        for m in members
    ]

    return JsonResponse({"results": data})

def confirm_promote_head(request, id):
    current_user = get_current_user(request)
    mymember = get_object_or_404(Member, id=id)

    if current_user.role.name not in ['secretariat', 'admin']:
        messages.error(request, "You are not allowed to perform this action.")
        return redirect('/main/members/')

    if mymember.role.name != 'member':
        messages.error(request, "This user cannot be promoted.")
        return redirect('/main/members/details/%d/' % mymember.id)

    if request.method == "POST":
        head_role = Role.objects.get(name='head')
        mymember.role = head_role
        mymember.save()

        messages.success(request, "Member promoted to Head.")
        return redirect('/main/members/details/%d/' % mymember.id)

    return render(request, 'confirm_action.html', {
        'title': 'Promote to Head',
        'message': f"Are you sure you want to promote {mymember.firstname} to Head?",
        'confirm_text': 'Promote',
    })

def confirm_promote_secretariat(request, id):
    current_user = get_current_user(request)
    mymember = get_object_or_404(Member, id=id)

    if not current_user or not current_user.role or current_user.role.name != 'admin':
        messages.error(request, "You are not allowed to perform this action.")
        return redirect('/main/members/')

    if mymember.role.name != 'head':
        messages.error(request, "Only a Head can be promoted to Secretariat.")
        return redirect(f'/main/members/details/{mymember.id}/')

    secretariat_count = Member.objects.filter(role__name='secretariat').count()
    if secretariat_count >= 2:
        messages.error(request, "Maximum of 2 Secretariats already assigned.")
        return redirect(f'/main/members/details/{mymember.id}/')

    if request.method == "POST":
        secretariat_role = Role.objects.get(name='secretariat')
        mymember.role = secretariat_role
        mymember.save()

        messages.success(request, "Head promoted to Secretariat.")
        return redirect(f'/main/members/details/{mymember.id}/')

    return render(request, 'confirm_action.html', {
        'title': 'Promote to Secretariat',
        'message': f"Are you sure you want to promote {mymember.firstname} to Secretariat?",
        'confirm_text': 'Promote',
    })

def confirm_demote_head(request, id):
    current_user = get_current_user(request)
    mymember = get_object_or_404(Member, id=id)

    if current_user.role.name not in ['secretariat', 'admin']:
        messages.error(request, "You are not allowed to perform this action.")
        return redirect('/main/members/details/')

    if mymember.role.name != 'head':
        messages.error(request, "This member is not a Head.")
        return redirect(f'/main/members/details/{mymember.id}/')

    if request.method == "POST":
        member_role = Role.objects.get(name='member')

        mymember.role = member_role
        mymember.headed_departments.clear()
        mymember.save()

        messages.success(request, "Head demoted to Member.")
        return redirect(f'/main/members/details/{mymember.id}/')

    return render(request, 'confirm_action.html', {
        'title': 'Demote Head',
        'message': f"Are you sure you want to demote {mymember.firstname} to Member?",
        'confirm_text': 'Demote',
    })

def confirm_demote_secretariat(request, id):
    current_user = get_current_user(request)
    mymember = get_object_or_404(Member, id=id)

    if current_user.role.name != 'admin':
        messages.error(request, "Only admin can perform this action.")
        return redirect('/main/members/')

    if mymember.role.name != 'secretariat':
        messages.error(request, "This member is not a Secretariat.")
        return redirect(f'/main/members/details/{mymember.id}/')

    if request.method == "POST":
        head_role = Role.objects.get(name='head')

        mymember.role = head_role
        mymember.save()

        messages.success(request, "Secretariat demoted to Head.")
        return redirect(f'/main/members/details/{mymember.id}/')

    return render(request, 'confirm_action.html', {
        'title': 'Demote Secretariat',
        'message': f"Are you sure you want to demote {mymember.firstname} to Head?",
        'confirm_text': 'Demote',
    })

def edit_member(request, id):
    current_user = get_current_user(request)
    mymember = get_object_or_404(Member, id=id)

    if not current_user:
        messages.error(request, "You must be logged in.")
        return redirect('/')

    can_edit_basic = (
        current_user.id == mymember.id or
        current_user.role.name in ['secretariat', 'admin']
    )

    if not can_edit_basic:
        messages.error(request, "You are not allowed to edit this member.")
        return redirect(f'/main/members/details/{mymember.id}/')

    if request.method == "POST":

        if 'profile_photo' in request.FILES:
            mymember.profile_photo = request.FILES['profile_photo']

        mymember.firstname = request.POST.get('firstname')
        mymember.lastname = request.POST.get('lastname')
        mymember.phone = request.POST.get('phone')
        mymember.email = request.POST.get('email')
        mymember.username = request.POST.get('username')

        if Member.objects.exclude(id=mymember.id).filter(username=mymember.username).exists():
            messages.error(request, "Username already exists.")
            return redirect(request.path)

        new_password = request.POST.get('password')
        if new_password:
            mymember.password = make_password(new_password)

        try:
            mymember.full_clean()
        except ValidationError as e:
            for errors in e.message_dict.values():
                for error in errors:
                    messages.error(request, error)
            return redirect(request.path)

        if current_user.role.name in ['secretariat', 'admin']:
            selected_departments = request.POST.getlist('departments')

            if mymember.role.name == 'head' and len(selected_departments) > 1:
                messages.error(request, "A Head can be assigned to only one department.")
                return redirect(request.path)

            if mymember.role.name == 'head':
                for dept_id in selected_departments:
                    head_count = Member.objects.filter(
                        role__name='head',
                        headed_departments__id=dept_id
                    ).exclude(id=mymember.id).count()

                    if head_count >= 2:
                        messages.error(request, "This department already has 2 heads.")
                        return redirect(request.path)

                mymember.headed_departments.set(selected_departments)

        mymember.save()
        messages.success(request, "Member updated successfully.")
        return redirect(f'/main/members/details/{mymember.id}/')

    context = {
        'mymember': mymember,
        'current_user': current_user,
        'can_manage_roles': current_user.role.name in ['secretariat', 'admin'],
        'departments': Department.objects.all(),
        'can_delete_member': can_delete_member(current_user, mymember),
    }
    return render(request, 'edit_member.html', context)

def logins(request):
    try:
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')

            try:
                user = Member.objects.get(username=username)
            except Member.DoesNotExist:
                user = None
                messages.error(request, "Invalid username or password")
                return render(request, "profile_form.html")

            if check_password(password, user.password):
                request.session['user_authenticated'] = True
                request.session['member_id'] = user.id
                return redirect('/main/')
            else:
                messages.error(request, "Invalid username or password")
                return render(request, 'profile_form.html')
            
        return render(request, 'profile_form.html')
    
    except Exception:
        traceback.print_exc()
        
def register(request):
    try:
        if request.method == "POST":
            firstname = request.POST.get("firstname")
            lastname = request.POST.get("lastname")
            username = request.POST.get("username")
            password = request.POST.get("password")
            confirmPassword = request.POST.get("confirmPassword")
            email = request.POST.get("email")
            phone = request.POST.get("phone")

            if Member.objects.filter(username=username).exists():
                messages.error(request, "Username already exists.")
                return render(request, "register.html")
            
            if Member.objects.filter(email=email).exists():
                messages.error(request, "Email already registered.")
                return render(request, "register.html")

            if password != confirmPassword:
                messages.error(request, "Passwords do not match.")
                return render(request, "register.html")
            
            if len(password) < 5:
                messages.error(request, "Password must be at least 5 characters long.")
                return render(request, "register.html")

            if username == password:
                messages.error(request, "Username and password cannot be the same.")
                return render(request, "register.html")

            if phone:
                if not re.fullmatch(r"\d{10}", phone):
                    messages.error(request, "Phone number must be exactly 10 digits.")
                    return render(request, "register.html")
                
            if Member.objects.filter(phone=phone).exists():
                messages.error(request, "Phone number already exists.")
                return render(request, "register.html")
                
            default_role, _ = Role.objects.get_or_create(name='member')

            Member.objects.create(
                firstname=firstname,
                lastname=lastname,
                username=username,
                password=make_password(password),
                email=email,
                phone=phone,
                role = default_role,
            )

            messages.success(request, "Account created successfully.")
            return redirect('/')

        return render(request, "register.html")

    except Exception:
        traceback.print_exc()

def add_member(request):
    current_user = get_current_user(request)

    if not can_manage_members(current_user):
        messages.error(request, "You are not allowed to add members.")
        return redirect('/main/members/')

    if request.method == "POST":
        firstname = request.POST.get("firstname")
        lastname = request.POST.get("lastname")
        username = request.POST.get("username")
        password = request.POST.get("password")
        email = request.POST.get("email")
        phone = request.POST.get("phone")

        if Member.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect(request.path)

        default_role = Role.objects.get(name='member')

        Member.objects.create(
            firstname=firstname,
            lastname=lastname,
            username=username,
            password=make_password(password),
            email=email,
            phone=phone,
            role=default_role
        )

        messages.success(request, "Member added successfully.")
        return redirect('/main/members/')

    return render(request, 'add_member.html')

def confirm_delete_member(request, id):
    current_user = get_current_user(request)
    mymember = get_object_or_404(Member, id=id)

    if not can_delete_member(current_user, mymember):
        messages.error(request, "You are not allowed to delete this member.")
        return redirect(f'/main/members/details/{mymember.id}/')

    if request.method == "POST":
        # Cleanup
        mymember.headed_departments.clear()
        mymember.delete()

        messages.success(request, "Member deleted successfully.")

        # Self delete → logout
        if current_user.id == mymember.id:
            request.session.flush()
            return redirect('/')

        return redirect('/main/members/')

    return render(request, 'confirm_action.html', {
        'title': 'Delete Member',
        'message': f"Are you sure you want to delete {mymember.firstname}?",
        'confirm_text': 'Delete',
        'danger': True,
    })

def testing(request):
    mydata = Member.objects.all().values()
    template = loader.get_template('template.html')
    context = {
        'mymembers': mydata,
    }
    return HttpResponse(template.render(context, request))

def logout(request):
    request.session.flush()
    return redirect('/')