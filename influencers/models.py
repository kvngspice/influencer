from django.db import models
from django.contrib.auth.models import User

# Define platform choices at the top level
PLATFORM_CHOICES = [
    ("X", "X (Twitter)"),
    ("Instagram", "Instagram"),
    ("TikTok", "TikTok"),
    ("Reddit", "Reddit"),
    ("YouTube", "YouTube"),
]

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[("client", "Client"), ("influencer", "Influencer")], default="client")

    def __str__(self):
        return f"{self.user.username} - {self.role}"

class Influencer(models.Model):
    PLATFORM_CHOICES = [
        ("X", "X (Twitter)"),
        ("Instagram", "Instagram"),
        ("TikTok", "TikTok"),
        ("YouTube", "YouTube"),
    ]

    name = models.CharField(max_length=255)
    platform = models.CharField(max_length=50, choices=PLATFORM_CHOICES)
    niche = models.CharField(max_length=100)
    followers_count = models.IntegerField()
    profile_picture = models.ImageField(upload_to='influencer_profiles/', null=True, blank=True)
    social_media_handle = models.CharField(max_length=100, default="@", blank=True)
    instagram_url = models.URLField(null=True, blank=True)
    tiktok_url = models.URLField(null=True, blank=True)
    youtube_url = models.URLField(null=True, blank=True)
    twitter_url = models.URLField(null=True, blank=True)
    interests = models.TextField(null=True, blank=True)
    demography = models.TextField(null=True, blank=True)
    region = models.CharField(max_length=100, default="Nigeria")
    base_fee = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        default=0.00,
        help_text="Minimum fee for booking this influencer"
    )

    def get_profile_picture(self):
        """Return a valid profile picture URL or default image"""
        if self.profile_picture and hasattr(self.profile_picture, 'url'):
            return self.profile_picture.url
        # Return a default profile picture URL
        return f"https://ui-avatars.com/api/?name={self.name.replace(' ', '+')}"

    def get_social_links(self):
        """Return a dictionary of social media links"""
        return {
            'instagram': self.instagram_url,
            'tiktok': self.tiktok_url,
            'youtube': self.youtube_url,
            'twitter': self.twitter_url
        }

    def __str__(self):
        return self.name

    def is_within_budget(self, budget):
        """Check if influencer's base fee is within the given budget"""
        return float(self.base_fee) <= float(budget)

from django.db import models

class Campaign(models.Model):
    owner = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='campaigns',
        null=True,
        blank=True
    )
    PLATFORM_CHOICES = [
        ("X", "X (Twitter)"),
        ("Instagram", "Instagram"),
        ("TikTok", "TikTok"),
        ("Reddit", "Reddit"),
        ("YouTube", "YouTube"),
    ]
    name = models.CharField(max_length=255)
    objective = models.TextField()
    platforms = models.JSONField(default=list) 
    budget = models.DecimalField(max_digits=10, decimal_places=2)
    demography = models.CharField(max_length=50, default="18-24")  # Set default
    gender = models.CharField(max_length=10, choices=[("Male", "Male"), ("Female", "Female")], default="Male")
    region = models.CharField(max_length=100, default="Nigeria")
    industry = models.CharField(max_length=100, default="General")
    
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def is_assigned(self):
        return self.booking_set.exists()
    
    @property
    def assigned_influencers_count(self):
        return self.booking_set.count()
    
    @property
    def progress(self):
        if not self.is_assigned:
            return 0
        # Calculate progress based on completed deliverables or time
        # This is a simplified example
        return 50  # Replace with actual calculation

    def __str__(self):
        return self.name
    
class Booking(models.Model):
    campaign = models.ForeignKey(
        Campaign, 
        on_delete=models.CASCADE,
        related_name='bookings'
    )
    influencer = models.ForeignKey(
        Influencer, 
        on_delete=models.CASCADE,
        related_name='bookings'
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
            ('completed', 'Completed')
        ],
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.campaign.name} - {self.influencer.name}"
    
class InfluencerNotification(models.Model):
    influencer = models.ForeignKey('Influencer', on_delete=models.CASCADE)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.influencer.name} - {self.message}"

class Payment(models.Model):
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed')
    ])
    transaction_id = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payment for Booking #{self.booking.id} - {self.status}"