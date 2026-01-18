from django.shortcuts import render
from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from django.contrib.auth.decorators import login_required

# Example sensitive view (login or any critical endpoint)
@ratelimit(key='ip', rate='10/m', method='POST', block=True)  # for authenticated users
def login_view(request):
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        return JsonResponse({'error': 'Too many requests'}, status=429)

    # your login logic here
    return JsonResponse({'success': 'Login successful'})
