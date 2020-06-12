# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
module RedmineOidc
  # Simple wrapper class around the Redmine Settings, to allow validation
  class Settings
    include ActiveModel::Model

    VALID_KEYS = %w(enabled issuer_url client_id client_secret scope unique_id_claim)

    attr_accessor *VALID_KEYS.map(&:to_sym)

    validates :issuer_url, :client_id, :client_secret, :scope, presence: true, if: :enabled
    validates_url :issuer_url, if: :enabled

    class << self
      # Obtain an instance from the current Redmine configuration
      def current
        settings_hash = ::Setting.plugin_redmine_oidc
        settings_hash = settings_hash.reject { |k,_| !VALID_KEYS.include? k }

        new(settings_hash)
      end
    end

  end
end
