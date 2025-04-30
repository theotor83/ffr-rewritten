from django import template
from django.utils.safestring import mark_safe
from django.utils.html import escape
import re
import base64
import urllib.parse
from django.utils import timezone
from datetime import timedelta

# This is a file for all the template tags that were too hard to make work with precise_bbcode.
# It is not a good practice to use this file, and will probably get very messy later on, but it is easier to understand for now.

register = template.Library()

@register.filter
def process_video_tags(value):
    """Convert video tags to placeholders with base64-encoded URLs"""
    pattern = r'\[video\](.*?)\[/video\]'
    
    def replace_video_tag(match):
        url = match.group(1).strip()
        # Base64 encode the URL to prevent it from being recognized as a URL
        encoded_url = base64.b64encode(url.encode('utf-8')).decode('utf-8')
        return f'[VIDEO_ENCODED]{encoded_url}[/VIDEO_ENCODED]'
    
    # Replace all video tags with encoded placeholders
    processed_text = re.sub(pattern, replace_video_tag, value)
    return processed_text

@register.filter
def finalize_video_tags(value):
    """Convert encoded placeholders back to video tags with security validation"""
    pattern = r'\[VIDEO_ENCODED\](.*?)\[/VIDEO_ENCODED\]'
    
    def replace_placeholder(match):
        encoded_url = match.group(1)
        try:
            # Decode the base64 URL
            url = base64.b64decode(encoded_url.encode('utf-8')).decode('utf-8')
            
            url_is_safe = False
            
            # More thorough URL validation
            if url.startswith('https://'):
                # Parse the URL to validate its structure
                parsed_url = urllib.parse.urlparse(url)
                # Check if it has a valid netloc (domain) and no suspicious components
                if parsed_url.netloc and not any(c in url for c in ['"', "'", '<', '>', ';', ' ']):
                    url_is_safe = True
            
            if url_is_safe:
                # Escape the URL to prevent XSS
                safe_url = escape(url)
                return f'<video controls style="max-width: 500px; max-height: 500px;" ><source src="{safe_url}" type="video/mp4"></video>'
            else:
                return "[URL vidéo invalide]"
                
        except Exception as e:
            # Handle decoding errors safely
            return f"[Error processing video: {escape(str(e))}]"
    
    processed_text = re.sub(pattern, replace_placeholder, value)
    return mark_safe(processed_text)

@register.filter(name='is_within_minutes')
def is_within_minutes(value, minutes):
    """
    Checks if a datetime value is within the last N minutes from now.
    Returns True if the value is recent (within the specified minutes), False otherwise.
    """
    if not value:
        return False # Handle cases where last_login might be None

    try:
        minutes = int(minutes)
    except (ValueError, TypeError):
        return False # Invalid argument

    now = timezone.now()

    # Ensure timezone consistency if needed (important if settings.USE_TZ = True)
    if timezone.is_aware(now) and timezone.is_naive(value):
        # Assuming value should be in the default timezone if naive
        # You might need to adjust this based on your application's timezone handling
        value = timezone.make_aware(value, timezone.get_default_timezone())
    elif timezone.is_naive(now) and timezone.is_aware(value):
         # Less likely if USE_TZ=True, but handle for completeness
         now = timezone.make_aware(now, timezone.get_default_timezone())

    # Check if the datetime is greater than or equal to the time 'minutes' ago
    return value >= (now - timedelta(minutes=minutes))