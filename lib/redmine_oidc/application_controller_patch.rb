# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
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
