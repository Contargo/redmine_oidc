# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
module RedmineOidc
  class Hooks < Redmine::Hook::ViewListener
    render_on :view_account_login_bottom,
              :partial => 'hooks/oidc_login'
  end
end
