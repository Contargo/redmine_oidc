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
        logging_prefix = "#{debug_info}"
        logger.info "#{debug_info}: Trying to verify ID token"
        oidc_session = OidcSession.spawn(session)
        oidc_session.verify!
        logger.info "#{debug_info}: ID token verified"
      rescue OpenIDConnect::ResponseObject::IdToken::ExpiredToken => e
        logger.info "#{debug_info}: #{e.class} - #{e.message}"
        begin
          logger.info "#{debug_info}: Trying to refresh ID token."
          oidc_session.refresh!
          logger.info "#{debug_info}: ID token refreshed"
        rescue Rack::OAuth2::Client::Error => e
          logger.info "#{debug_info}: #{e.class} - #{e.message}"
          return true
        rescue HTTPClient::ConnectTimeoutError => e
          logger.info "Ignoring HTTPClient::ConnectTimeoutError to avoid 422."
          logger.info "#{debug_info}: #{e.class} - #{e.message} - #{e.backtrace}"
          return false
        rescue Exception => e
          logger.warn "#{debug_info}: #{e.class} - #{e.message}"
          return true
        end
      rescue Exception => e
        logger.warn "#{debug_info}: #{e.class} - #{e.message}"
        return true
      end
      false
    end

    def verify_authenticity_token # :doc:
      mark_for_same_origin_verification!

      if !verified_request?
        if logger && log_warning_on_csrf_failure
          if valid_request_origin?
            logger.warn "#{debug_info}: Can't verify CSRF token authenticity. (#{find_current_user})"
          else
            logger.warn "HTTP Origin header (#{request.origin}) didn't match request.base_url (#{request.base_url})"
          end
        end
        handle_unverified_request
      end
    end

    AUTHENTICITY_TOKEN_LENGTH = 32

    # Checks the client's masked token to see if it matches the
    # session token. Essentially the inverse of
    # +masked_authenticity_token+.
    def valid_authenticity_token?(session, encoded_masked_token) # :doc:
      if encoded_masked_token.nil? || encoded_masked_token.empty? || !encoded_masked_token.is_a?(String)
        return false
      end

      begin
        masked_token = decode_csrf_token(encoded_masked_token)
      rescue ArgumentError # encoded_masked_token is invalid Base64
        return false
      end

      # See if it's actually a masked token or not. In order to
      # deploy this code, we should be able to handle any unmasked
      # tokens that we've issued without error.

      if masked_token.length == AUTHENTICITY_TOKEN_LENGTH
        # This is actually an unmasked token. This is expected if
        # you have just upgraded to masked tokens, but should stop
        # happening shortly after installing this gem.
        compare_with_real_token masked_token, session

      elsif masked_token.length == AUTHENTICITY_TOKEN_LENGTH * 2
        csrf_token = unmask_token(masked_token)

        state = false
        if compare_with_global_token(csrf_token, session)
          state_global = true
          logger.info "#{debug_info}: compare_with_global_token successful"
        else
          state_global = false
          logger.warn "#{debug_info}: compare_with_global_token failed"
        end
        if compare_with_real_token(csrf_token, session)
          state_real = true
          logger.info "#{debug_info}: compare_with_real_token successful"
        else
          state_real = false
          logger.warn "#{debug_info}: compare_with_real_token failed"
        end
        if valid_per_form_csrf_token?(csrf_token, session)
          state_form = true
          logger.info "#{debug_info}: valid_per_form_token successful"
        else
          state_form = false
          logger.warn "#{debug_info}: valid_per_form_token failed"
        end
        state = state_global || state_real || state_form
        if !state
          user = find_current_user
          logger.info "#{debug_info} Parameter authenticity token: " + encode_csrf_token(csrf_token)
          logger.info "#{debug_info} Session real authenticity token : " + session[:_csrf_token]
          logger.info "#{debug_info} Session global authenticity token : " + encode_csrf_token(global_csrf_token(session))
        end
        state
      else
        false # Token is malformed.
      end
    end

    def debug_info
      user = (session[:user_id] ? "#{session[:user_id]}" : "anonymous")
      "uid=#{user}@session=#{session.id} requesting #{request.original_fullpath}"
    end

  end

end

unless ApplicationController.included_modules.include?(RedmineOidc::ApplicationControllerPatch)
  ApplicationController.prepend(RedmineOidc::ApplicationControllerPatch)
end
