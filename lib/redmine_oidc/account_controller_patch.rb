# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
module RedmineOidc
  module AccountControllerPatch

    def login
      return super unless RedmineOidc.settings.enabled

      # TODO: check if direct controller call works
      redirect_to oidc_login_url
    end

    def logout
      return super unless RedmineOidc.settings.enabled

      # TODO: check if direct controller call works
      redirect_to oidc_logout_url
    end

  end
end
