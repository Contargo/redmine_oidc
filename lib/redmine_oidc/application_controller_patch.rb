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
          url = url_for(:controller => params[:controller], :action => params[:action], :id => params[:id], :project_id => params[:project_id])
        end
        session[:back_url] = url
        redirect_to oidc_login_url
        return false
      end
    end

    def session_expired?
      return super unless RedmineOidc.settings.enabled

      begin
        oidc_session = OidcSession.spawn(session)
        oidc_session.verify!
      rescue OpenIDConnect::ResponseObject::IdToken::ExpiredToken
        begin
          oidc_session.refresh!
        rescue Rack::OAuth2::Client::Error
          return true
        end
      rescue Exception
        return true
      end
      false
    end
  end
end

unless ApplicationController.included_modules.include?(RedmineOidc::ApplicationControllerPatch)
  ApplicationController.prepend(RedmineOidc::ApplicationControllerPatch)
end
