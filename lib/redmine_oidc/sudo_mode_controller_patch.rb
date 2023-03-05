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

require 'repost'

module RedmineOidc
  module SudoModeControllerPatch
    def require_sudo_mode(*param_names)
      return super unless RedmineOidc.settings.enabled
      return super unless RedmineOidc.settings.sudo_mode_reauthenticate

      return true if Redmine::SudoMode.active?

      if OidcSession.spawn(session).auth_time > Redmine::SudoMode.timeout.ago.to_i
        logger.info "Activating sudo mode for user #{User.current.login}"
        Redmine::SudoMode.active!
      end

      # Note: This method must be called even right after `Redmine::SudoMode.active!`
      # because despite its name, it has side effects!
      return true if Redmine::SudoMode.active?

      if param_names.blank?
        # This list was copied from the original `require_sudo_mode`, but without `_method`.
        param_names = params.keys - %w(id action controller authenticity_token utf8)
      end

      back_url = url_for(**params.slice(:controller, :action, :id, :project_id).to_unsafe_hash)

      session[:oidc_sudo_deferred] = {
        back_url: back_url,
        params: params.slice(*param_names).to_unsafe_hash,
        options: {
          method: request.method_symbol,
          authenticity_token: :auto,
        },
      }

      logger.info "Reauthenticating #{User.current.login} for sudo mode"
      redirect_to oidc_login_path(back_url: back_url, reauth: true)

      false
    end
  end
end

unless Redmine::SudoMode::Controller.included_modules.include?(RedmineOidc::SudoModeControllerPatch)
  Redmine::SudoMode::Controller.prepend(RedmineOidc::SudoModeControllerPatch)
end
