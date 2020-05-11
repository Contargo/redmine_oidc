require 'openid_connect'

class OidcController < ApplicationController

  def login
    oidc_client.redirect_uri = oidc_callback_url

    nonce = new_nonce

    redirect_to oidc_client.authorization_uri(
        nonce: nonce,
        state: nonce,
        scope: oidc_config.scopes_supported & [:openid, :email, :profile, :address].collect(&:to_s),
    )
  end

  def callback
    oidc_client.redirect_uri = oidc_callback_url
    oidc_client.authorization_code = params[:code]
    access_token = oidc_client.access_token!
    _id_token_ = decode_id access_token.id_token
    _id_token_.verify!(
        issuer: RedmineOidc.settings['issuer_url'],
        client_id: RedmineOidc.settings['client_id'],
        nonce: stored_nonce
    )
    @id_token = _id_token_
  end
  private

  def oidc_client
    @oidc_client ||= OpenIDConnect::Client.new(
        identifier: RedmineOidc.settings['client_id'],
        secret: RedmineOidc.settings['client_secret'],
        authorization_endpoint: oidc_config.authorization_endpoint,
        token_endpoint: oidc_config.token_endpoint,
        userinfo_endpoint: oidc_config.userinfo_endpoint,
        jwks_uri: oidc_config.jwks_uri,
        scopes_supported: oidc_config.scopes_supported
    )
  end

  def oidc_config
    @oidc_config ||= OpenIDConnect::Discovery::Provider::Config.discover! RedmineOidc.settings['issuer_url']

  rescue OpenIDConnect::Discovery::DiscoveryFailed => e


  end

  def new_nonce
    session[:nonce] = SecureRandom.hex(16)
  end

  def stored_nonce
    n = session[:nonce]
    session.delete(:nonce)
    n
  end

  def decode_id(id_token)
    OpenIDConnect::ResponseObject::IdToken.decode id_token, oidc_config.jwks
  end

end
