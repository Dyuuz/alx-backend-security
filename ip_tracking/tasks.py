from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

# Thresholds
MAX_REQUESTS_PER_HOUR = 100
SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_suspicious_ips():
    """
    Flags IPs that exceed 100 requests/hour or access sensitive paths.
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # Count requests per IP in the last hour
    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
    ip_counts = {}
    for log in logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

    # Flag IPs exceeding threshold
    for ip, count in ip_counts.items():
        if count > MAX_REQUESTS_PER_HOUR:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={'reason': f'Exceeded {MAX_REQUESTS_PER_HOUR} requests/hour'}
            )

    # Flag IPs accessing sensitive paths
    sensitive_logs = logs.filter(path__in=SENSITIVE_PATHS)
    for log in sensitive_logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            defaults={'reason': f'Accessed sensitive path {log.path}'}
        )

    return f"Suspicious IP detection completed at {timezone.now()}"
