from .models import Member

def get_current_user(request):
    member_id = request.session.get('member_id')
    if not member_id:
        return None
    try:
        return Member.objects.get(id=member_id)
    except Member.DoesNotExist:
        return None

def can_manage_members(user):
    if not user or not user.role:
        return False
    return user.role.name in ['head', 'secretariat', 'admin']

def can_delete_member(current_user, target_member):
    if not current_user:
        return False

    if current_user.id == target_member.id:
        return True  # self-delete

    hierarchy = {
        'member': 1,
        'head': 2,
        'secretariat': 3,
        'admin': 4,
    }

    return hierarchy[current_user.role.name] > hierarchy[target_member.role.name]
