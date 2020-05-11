require 'redmine_oidc'

Redmine::Plugin.register :redmine_oidc do
  name 'Redmine OpenId Connect plugin'
  author 'Contargo GmbH & Co. KG'
  description 'Add login with OpenId Connect as another login option'
  version '0.0.1'
  url 'https://github.com/Contargo/redmine_oidc'
  author_url 'https://contargo.net'
  settings :default => {:issuer_url => false,
                        :client_id => false,
                        :client_secret => false},
           :partial => 'settings/redmine_oidc'
end
