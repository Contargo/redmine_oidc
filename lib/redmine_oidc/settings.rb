# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
module RedmineOidc
  # Simple wrapper class around the Redmine Settings, to allow validation
  class Settings
    include ActiveModel::Model
    include ActiveModel::Serialization

    VALID_KEYS = %w(
      enabled
      issuer_url
      client_id
      client_secret
      scope
      unique_id_claim
      roles_claim
      access_roles
      admin_role
    )

    attr_accessor *VALID_KEYS.map(&:to_sym)

    validates :issuer_url, :client_id, :client_secret, :scope, :unique_id_claim, :roles_claim, :access_roles, :admin_role, presence: true, if: :enabled
    validates_url :issuer_url, if: :enabled

    class << self
      # Obtain an instance from the current Redmine configuration
      def current
        settings_hash = ::Setting.plugin_redmine_oidc
        settings_hash = settings_hash.reject { |k,_| !VALID_KEYS.include? k.to_s }

        new(settings_hash)
      end
    end

    def attributes
      VALID_KEYS.map {|key| [key, nil]}.to_h
    end

    def merge(settings)
      self.class.new(to_h.merge(settings.to_h) { |key, v1, v2| v2.present? ? v2 : v1 })
    end

    def to_h
      serializable_hash
    end

  end
end
