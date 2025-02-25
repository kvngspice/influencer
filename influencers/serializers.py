from rest_framework import serializers
from .models import Campaign, Influencer, Booking


class CampaignSerializer(serializers.ModelSerializer):
    platforms = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    
    class Meta:
        model = Campaign
        fields = "__all__"

    def validate(self, data):
        # Ensure platforms is a list
        if 'platforms' in data and not isinstance(data['platforms'], list):
            if isinstance(data['platforms'], str):
                data['platforms'] = [data['platforms']]
            else:
                data['platforms'] = list(data['platforms'])
        
        # Set default values if not provided
        if 'platforms' not in data:
            data['platforms'] = []
            
        return data

    def create(self, validated_data):
        try:
            return super().create(validated_data)
        except Exception as e:
            print(f"Error creating campaign: {str(e)}")  # Debug print
            raise serializers.ValidationError(f"Failed to create campaign: {str(e)}")


class InfluencerSerializer(serializers.ModelSerializer):
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = Influencer
        fields = [
            'id', 'name', 'platform', 'followers_count', 
            'profile_picture', 'niche', 'social_media_handle', 
            'region', 'interests', 'demography', 'base_fee',
            'instagram_url', 'tiktok_url', 'youtube_url', 'twitter_url'
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
        
        instance.save()
        return instance

    def get_profile_picture(self, obj):
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
        return None

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Add debug print
        print(f"Serializing influencer {instance.id}: base_fee = {instance.base_fee}")
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

        
        