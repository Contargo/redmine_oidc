# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
class OidcSession
  include ActiveModel::Model
  include ActiveModel::Serialization

  attr_accessor :session, :redirect_uri, :state, :nonce, :code, :session_state
  attr_accessor :id_token, :access_token, :refresh_token

  private_class_method :new

  SESSION_KEY = :oidc_session

  def self.spawn(session)
    if session[SESSION_KEY].present?
      new(session[SESSION_KEY].merge({session: session}))
    else
      new(session: session)
    end
  end

  def authorization_endpoint(redirect_uri:)
    @redirect_uri = redirect_uri
    save!
    oidc_client.authorization_uri(
      nonce: oidc_nonce,
      state: oidc_nonce,
      scope: oidc_scope,
    )
  end

  def end_session_endpoint(post_logout_redirect_uri:)
    return if oidc_config.end_session_endpoint.nil?
    oidc_config.end_session_endpoint + '?' + end_session_query(post_logout_redirect_uri)
  end

  def update!(params)
    @session_state = params[:session_state]
    @code = params[:code]
    save!
  end

  def acquire!
    oidc_client.authorization_code = @code
    parse(oidc_client.access_token!)
  end

  def refresh!
    oidc_client.refresh_token = @refresh_token
    parse(oidc_client.access_token!)
  end

  def destroy!
    session.delete(SESSION_KEY)
  end

  def complete?
    @id_token.present?
  end

  def verify!
    decoded_id_token.verify!(
      issuer: settings.issuer_url,
      client_id: settings.client_id,
      nonce: oidc_nonce,
    )
  end

  def oidc_identifier
    @oidc_indentifier ||= decoded_id_token.raw_attributes[settings.unique_id_claim]
  end

  def user_attributes
    attributes = decoded_id_token.raw_attributes
    {
      oidc_identifier: oidc_identifier,
      login: attributes['preferred_username'],
      firstname: attributes['given_name'],
      lastname: attributes['family_name'],
      mail: attributes['email'],
      avatar_url: attributes['picture'],
      admin: roles.include?(admin_role),
    }
  end

  def authorized?
    not access_roles.disjoint?(roles)
  end

  def save!
    @session[SESSION_KEY] = self.serializable_hash
  end

  private

  def parse(access_token)
    @access_token = access_token.access_token
    @refresh_token = access_token.refresh_token
    @id_token = access_token.id_token
    save!
  end

  def roles
    @roles ||= decoded_id_token.raw_attributes[settings.roles_claim].map(&:downcase).to_set
  end

  def access_roles
    @access_roles ||= settings.access_roles.split(' ').map(&:downcase).map(&:strip).to_set
  end

  def admin_role
    @admin_role ||= settings.admin_role.strip.downcase
  end

  def end_session_query(uri)
    query = {
      'session_state' => @session_state,
      'post_logout_redirect_uri' => uri,
    }
    if @id_token.present?
      query['id_token_hint'] = id_token
    end
    query.to_param
  end

  def oidc_client
    @oidc_client ||= OpenIDConnect::Client.new(
      identifier: settings.client_id,
      secret: settings.client_secret,
      authorization_endpoint: oidc_config.authorization_endpoint,
      token_endpoint: oidc_config.token_endpoint,
      userinfo_endpoint: oidc_config.userinfo_endpoint,
      jwks_uri: oidc_config.jwks_uri,
      scopes_supported: oidc_config.scopes_supported,
      redirect_uri: @redirect_uri,
    )
  end

  def oidc_scope
    scope = oidc_config.scopes_supported & [:openid, :email, :profile, :address].collect(&:to_s)
    @scope ||= scope & settings.scope.split unless (settings.scope.nil? || settings.scope.empty?)
  end

  def decoded_id_token
    raise Exception unless @id_token.present?
    @decoded_id_token ||= OpenIDConnect::ResponseObject::IdToken.decode(@id_token, oidc_config.jwks)
  end

  def oidc_config
    @oidc_config ||= with_configured_url_builder do
      OpenIDConnect::Discovery::Provider::Config.discover! settings.issuer_url
    end
  rescue OpenIDConnect::Discovery::DiscoveryFailed => e
  end

  def oidc_nonce
    if !@nonce
      @nonce = SecureRandom.uuid
      save!
    end
    @nonce
  end

  def settings
    @settings ||= RedmineOidc.settings
  end

  def attributes
    {
      'redirect_uri' => nil,
      'state' => nil,
      'nonce' => nil,
      'code' => nil,
      'session_state' => nil,
      'id_token' => nil,
      'access_token' => nil,
      'refresh_token' => nil,
    }
  end

  ##
  # Set temporary URL builder scheme
  #
  # The client library {SWD}[https://github.com/nov/swd] is used by the
  # {OpendIDConnect}[https://github.com/nov/openid_connect] library to process
  # web discovery. By default it accesses resources via +URI::HTTPS+, i.e.
  # secure connections, which makes perfect sense in a production context. In a
  # local development environment we do not have or want to use secure
  # communication. To achieve this we set the url builder based on the issuer
  # url scheme. We also reset the url builder to its previous value, since SWD
  # is a singleton and thus, might be set elsewhere.
  def with_configured_url_builder
    cached_url_builder = SWD.url_builder
    SWD.url_builder = URI.scheme_list[URI(settings.issuer_url).scheme.upcase]
    result = yield
    SWD.url_builder = cached_url_builder
    return result
  end

end
