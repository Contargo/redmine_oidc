# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
module RedmineOidc
  module AvatarsHelperPatch

    def self.prepended(base)
      base.class_eval do
        include InstanceMethods

        alias_method :avatar_without_oidc, :avatar
        alias_method :avatar, :avatar_with_oidc
      end
    end

    module InstanceMethods
      def avatar_with_oidc(user, options = {})
        if RedmineOidc.settings.enabled and user.avatar_url.present?
          options[:class] = GravatarHelper::DEFAULT_OPTIONS[:class] + " " + options[:class] if options[:class]
          [:class, :alt, :title].each {|opt| options[opt] = h(options[opt])}
          image_tag(h(user.avatar_url), options)
        else
          avatar_without_oidc(user, options)
        end
      end
    end

  end
end

unless AvatarsHelper.included_modules.include?(RedmineOidc::AvatarsHelperPatch)
  AvatarsHelper.prepend(RedmineOidc::AvatarsHelperPatch)
end
