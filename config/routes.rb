# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG

Rails.application.routes.draw do
  get 'oidc/login', :to => 'oidc#login', :as => 'oidc_login'
  get 'oidc/callback', :to => 'oidc#callback', :as => 'oidc_callback'
  get 'oidc/logout', :to => 'oidc#logout', :as => 'oidc_logout'
  get 'oidc/local_logout', :to => 'oidc#local_logout', :as => 'oidc_local_logout'
end
