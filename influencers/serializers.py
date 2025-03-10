from rest_framework import serializers
from .models import Campaign, Influencer, Booking
import json


class CampaignSerializer(serializers.ModelSerializer):
    platforms = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    platforms_text = serializers.CharField(required=False)
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    bookings = serializers.SerializerMethodField()
    
    class Meta:
        model = Campaign
        fields = [
            'id', 
            'name', 
            'objective', 
            'platforms',
            'platforms_text',
            'budget', 
            'demography', 
            'gender', 
            'region', 
            'industry', 
            'bookings',
            'owner'
        ]

    def validate(self, data):
        data = super().validate(data)
        
        # Ensure platforms is a list
        if 'platforms' in data and not isinstance(data['platforms'], list):
            if isinstance(data['platforms'], str):
                data['platforms'] = [data['platforms']]
            else:
                data['platforms'] = list(data['platforms'])
        
        # Set default values if not provided
        if 'platforms' not in data:
            data['platforms'] = []
            
        # Generate platforms_text from platforms
        data['platforms_text'] = ', '.join(data.get('platforms', []))
        
        # Convert "All" gender to a valid choice
        if data.get('gender') == 'All':
            data['gender'] = 'Male'  # Or any other default value accepted by your model
            
        return data

    def create(self, validated_data):
        try:
            return super().create(validated_data)
        except Exception as e:
            print(f"Error creating campaign: {str(e)}")  # Debug print
            raise serializers.ValidationError(f"Failed to create campaign: {str(e)}")

    def get_bookings(self, obj):
        bookings = []
        for booking in obj.bookings.all():
            booking_data = {
                'id': booking.id,
                'status': booking.status,
                'influencer_id': booking.influencer.id
            }
            # Check if there's a payment for this booking
            try:
                payment = booking.payment_set.first()
                if payment and payment.status == 'completed':
                    booking_data['status'] = 'paid'
            except Exception as e:
                print(f"Error checking payment status: {str(e)}")
            
            bookings.append(booking_data)
        return bookings


class InfluencerSerializer(serializers.ModelSerializer):
    profile_picture = serializers.SerializerMethodField()
    user_username = serializers.SerializerMethodField(read_only=True)
    social_platforms = serializers.JSONField(required=False, default=list)

    class Meta:
        model = Influencer
        fields = [
            'id', 'name', 'platform', 'followers_count', 
            'profile_picture', 'niche', 'social_media_handle', 
            'region', 'interests', 'demography', 'base_fee',
            'instagram_url', 'tiktok_url', 'youtube_url', 'twitter_url',
            'user_username',
            'social_platforms'
        ]

    def validate_followers_count(self, value):
        try:
            value = int(value)
            if value < 0:
                raise serializers.ValidationError("Followers count must be a positive number")
            return value
        except (TypeError, ValueError):
            raise serializers.ValidationError("Followers count must be a valid number")

    def validate_url_field(self, value):
        """Validate URL fields"""
        if value and isinstance(value, str) and not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("Enter a valid URL starting with http:// or https://")
        return value

    def validate_profile_picture(self, value):
        """
        Don't validate profile_picture as URL since it's a file upload
        """
        return value  # Just return the uploaded file

    def validate_instagram_url(self, value):
        return self.validate_url_field(value)

    def validate_tiktok_url(self, value):
        return self.validate_url_field(value)

    def validate_youtube_url(self, value):
        return self.validate_url_field(value)

    def validate_twitter_url(self, value):
        return self.validate_url_field(value)

    def validate_base_fee(self, value):
        try:
            value = float(value)
            if value < 0:
                raise serializers.ValidationError("Base fee must be a positive number")
            return value
        except (TypeError, ValueError):
            raise serializers.ValidationError("Base fee must be a valid number")

    def validate_social_platforms(self, value):
        """
        Ensure social_platforms is a valid list
        """
        print(f"Validating social_platforms: {value}, type: {type(value)}")
        
        # If it's None or empty, return an empty list
        if not value:
            return []
        
        # If it's already a list, use it
        if isinstance(value, list):
            return value
        
        # If it's a string, try to parse it
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return []
        
        # For any other type, return an empty list
        return []

    def update(self, instance, validated_data):
        """
        Update and return an existing Influencer instance
        """
        instance.name = validated_data.get('name', instance.name)
        instance.platform = validated_data.get('platform', instance.platform)
        instance.niche = validated_data.get('niche', instance.niche)
        instance.followers_count = validated_data.get('followers_count', instance.followers_count)
        instance.profile_picture = validated_data.get('profile_picture', instance.profile_picture)
        instance.social_media_handle = validated_data.get('social_media_handle', instance.social_media_handle)
        instance.region = validated_data.get('region', instance.region)
        instance.interests = validated_data.get('interests', instance.interests)
        instance.demography = validated_data.get('demography', instance.demography)
        instance.base_fee = validated_data.get('base_fee', instance.base_fee)
        instance.social_platforms = validated_data.get('social_platforms', instance.social_platforms)
        instance.bio = validated_data.get('bio', instance.bio)
        instance.instagram_url = validated_data.get('instagram_url', instance.instagram_url)
        instance.tiktok_url = validated_data.get('tiktok_url', instance.tiktok_url)
        instance.youtube_url = validated_data.get('youtube_url', instance.youtube_url)
        instance.twitter_url = validated_data.get('twitter_url', instance.twitter_url)
        
        instance.save()
        return instance

    def get_profile_picture(self, obj):
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
        return None

    def get_user_username(self, obj):
        return obj.user.username if obj.user else None

    def to_representation(self, instance):
        data = super().to_representation(instance)
        
        # Convert social_platforms from string to JSON if needed
        if isinstance(data.get('social_platforms'), str):
            try:
                data['social_platforms'] = json.loads(data['social_platforms'])
            except (json.JSONDecodeError, TypeError):
                data['social_platforms'] = []
        
        return data


class BookingSerializer(serializers.ModelSerializer):
    campaign = CampaignSerializer(read_only=True)
    influencer = InfluencerSerializer(read_only=True)
    campaign_id = serializers.IntegerField(write_only=True)
    influencer_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Booking
        fields = [
            'id', 
            'campaign', 
            'campaign_id',
            'influencer', 
            'influencer_id',
            'status', 
            'created_at'
        ]

    def create(self, validated_data):
        # Convert the IDs to actual objects when creating
        campaign_id = validated_data.pop('campaign_id')
        influencer_id = validated_data.pop('influencer_id')
        
        campaign = Campaign.objects.get(id=campaign_id)
        influencer = Influencer.objects.get(id=influencer_id)
        
        return Booking.objects.create(
            campaign=campaign,
            influencer=influencer,
            **validated_data
        )

        
        