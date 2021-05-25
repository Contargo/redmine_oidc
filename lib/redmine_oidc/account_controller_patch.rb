# OpenID Connect Authentication for Redmine
# Copyright (C) 2020-2021 Contargo GmbH & Co. KG
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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
