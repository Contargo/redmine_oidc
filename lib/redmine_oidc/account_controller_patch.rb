# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
module RedmineOidc
  module AccountControllerPatch

    def login
      return super unless RedmineOidc.settings.enabled
      redirect_to oidc_login_url
    end

    def logout
      return super unless RedmineOidc.settings.enabled
      redirect_to oidc_logout_url
    end

  end
end

unless AccountController.included_modules.include?(RedmineOidc::AccountControllerPatch)
  AccountController.prepend(RedmineOidc::AccountControllerPatch)
end
