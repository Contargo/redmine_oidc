# OpenID Connect Authentication for Redmine
# Copyright (C) 2020-2021 Contargo GmbH & Co. KG
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# We use alias_method here to prepend AvartarsHelper patches introduced in the
# same way by the redmine_people plugin, for example.
module RedmineOidc
  module AvatarsHelperPatch

    def self.included(base)
      base.class_eval do
        include InstanceMethods

        alias_method :avatar_without_oidc, :avatar
        alias_method :avatar, :avatar_with_oidc
      end
    end

    module InstanceMethods
      def avatar_with_oidc(user, options = {})
        if RedmineOidc.settings.enabled && user.is_a?(User) && user.avatar_url.present?
          options[:class] = GravatarHelper::DEFAULT_OPTIONS[:class] + " " + options[:class] if options[:class]
          options = GravatarHelper::DEFAULT_OPTIONS.merge(options)
          [:class, :alt, :title].each {|opt| options[opt] = h(options[opt])}
          image_tag(h(user.avatar_url), options.except(:rating, :default, :ssl))
        else
          avatar_without_oidc(user, options)
        end
      end
    end

  end
end

unless AvatarsHelper.included_modules.include?(RedmineOidc::AvatarsHelperPatch)
  AvatarsHelper.include(RedmineOidc::AvatarsHelperPatch)
end
