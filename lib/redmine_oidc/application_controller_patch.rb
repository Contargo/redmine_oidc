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
  module ApplicationControllerPatch

    # A logged out, i.e. an anonymous user, must be redirected to the OIDC login
    def require_login
      return super unless RedmineOidc.settings.enabled

      if !User.current.logged?
        if request.get?
          url = request.original_url
        else
          url = url_for(controller: params[:controller], action: params[:action], id: params[:id], project_id: params[:project_id])
        end
        redirect_to oidc_login_path(back_url: url)
        return false
      end
    end

    def session_expired?
      return super unless RedmineOidc.settings.enabled

      begin
        user = (session[:user_id] ? "uid=#{session[:user_id]}" : "anonymous")
        logger.info "#{user}: Trying to verify ID token"
        oidc_session = OidcSession.spawn(session)
        oidc_session.verify!
        logger.info "#{user}: ID token verified"
      rescue OpenIDConnect::ResponseObject::IdToken::ExpiredToken => e
        logger.info "#{user}: #{e.class} - #{e.message}"
        begin
          logger.info "#{user}: Trying to refresh ID token."
          oidc_session.refresh!
          logger.info "#{user}: ID token refreshed"
        rescue Rack::OAuth2::Client::Error => e
          logger.info "#{user}: #{e.class} - #{e.message}"
          return true
        end
      rescue Exception => e
        logger.warn "#{user}: #{e.class} - #{e.message}"
        return true
      end
      false
    end
  end
end

unless ApplicationController.included_modules.include?(RedmineOidc::ApplicationControllerPatch)
  ApplicationController.prepend(RedmineOidc::ApplicationControllerPatch)
end
