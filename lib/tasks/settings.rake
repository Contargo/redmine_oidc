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
