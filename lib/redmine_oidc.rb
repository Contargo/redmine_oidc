# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
Rails.configuration.to_prepare do
  require_dependency 'redmine_oidc/account_controller_patch'
  require_dependency 'redmine_oidc/application_controller_patch'
end

module RedmineOidc
  def self.settings
    RedmineOidc::Settings.current
  end
end
