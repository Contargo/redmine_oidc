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

namespace :redmine do
  namespace :plugins do
    namespace :redmine_oidc do
      ENV_PREFIX = 'REDMINE_PLUGINS_REDMINE_OIDC_'

      desc 'Configure Redmine OpenId Connect plugin by environment'
      task :configure => :environment do
        current_settings = RedmineOidc.settings
        new_settings = build_new_settings
        merged_settings = current_settings.merge(new_settings)
        validate_settings(merged_settings)
        Setting.plugin_redmine_oidc = ActiveSupport::HashWithIndifferentAccess.new(merged_settings.to_h)
      end

      def build_new_settings
        settings_hash = {}
        RedmineOidc::Settings::VALID_KEYS.each do |key|
          settings_hash[key] = ENV["#{ENV_PREFIX}#{key.upcase}"]
        end
        RedmineOidc::Settings.new(settings_hash)
      end

      def validate_settings(settings)
        if !settings.valid?
          output = settings.errors.messages.map {|key, message| "#{ENV_PREFIX}#{key.upcase} #{message.join(' and ')}"}.join("\n")
          raise StandardError.new(output)
        end
      end

    end
  end
end
