from django.db import models

class RequestLog(models.Model):
    ip_address = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=255)
    city = models.CharField(max_length=255)

class BlockedIP(models.Model):
    ip_address = models.CharField(max_length=255)
    request_log = models.ForeignKey(RequestLog, null=True, blank=True, on_delete=models.SET_NULL)

# New model for Task 4
class SuspiciousIP(models.Model):
    ip_address = models.CharField(max_length=255, unique=True)
    reason = models.TextField()
    flagged_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.reason}"