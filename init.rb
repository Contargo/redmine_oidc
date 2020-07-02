require 'redmine_oidc'
require 'redmine_oidc/application_controller_patch'

Redmine::Plugin.register :redmine_oidc do
  name 'Redmine OpenId Connect plugin'
  author 'Contargo GmbH & Co. KG'
  description 'Add login with OpenId Connect as another login option'
  version '0.0.1'
  url 'https://github.com/Contargo/redmine_oidc'
  author_url 'https://contargo.net'
  settings :default => {:enabled => false},
           :partial => 'settings/redmine_oidc'
end

Rails.configuration.to_prepare do
  ApplicationController.prepend(RedmineOidc::ApplicationControllerPatch)
  AccountController.prepend(RedmineOidc::AccountControllerPatch)
end
