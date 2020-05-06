# Plugin's routes
# See: http://guides.rubyonrails.org/routing.html

Rails.application.routes.draw do
  get 'oidc/login', :to => 'oidc#login', :as => 'oidc_login'
  get 'oidc/callback', :to => 'oidc#callback', :as => 'oidc_callback'
end
