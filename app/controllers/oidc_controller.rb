# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
require 'openid_connect'

class OidcController < ApplicationController

  skip_before_action :check_if_login_required

  def login
    oidc_session = OidcSession.spawn(session)
    oidc_session.verify!
  rescue OpenIDConnect::ResponseObject::IdToken::ExpiredToken
    begin
      oidc_session.refresh!
    rescue Rack::OAuth2::Client::Error
    end
  rescue Exception
  ensure
    redirect_to OidcSession.spawn(session).authorization_endpoint
  end

  def callback
    oidc_session = OidcSession.spawn(session)
    oidc_session.update!(params)
    oidc_session.acquire!
    login_user
  end

  def logout
    oidc_session = OidcSession.spawn(session)
    if oidc_session.complete?
      oidc_session.destroy!
      logout_user
      reset_session
      redirect_to oidc_session.end_session_endpoint
    else
      redirect_to oidc_local_logout_url
    end
  end

  def local_logout
    logout_user
    reset_session
    redirect_to oidc_login_url
  end

  private

  def login_user
    @settings = RedmineOidc.settings
    @id_token = OidcSession.spawn(session).decoded_id_token
    user = User.find_by_oidc_identifier(@id_token[@settings.unique_id_claim])
    if user.nil?
      create_user
    else
      update_user(user)
    end
  end

  def create_user
    user = User.new do |u|
      u.oidc_identifier = @id_token[@settings.unique_id_claim]
      u.login = @id_token['preferred_username']
      u.firstname = @id_token['given_name']
      u.lastname = @id_token['family_name']
      u.mail = @id_token['email']
      u.random_password
      u.register
    end
    register_user(user)
  end

  def update_user(user)
    user.update_last_login_on!
    if session[:back_url]
      params[:back_url] = session[:back_url]
      session[:back_url] = nil
    end
    successful_authentication(user)
  end

  def register_user(user)
    user.activate
    user.last_login_on = Time.now
    if user.save
      successful_authentication(user)
    else
      user.errors.full_messages.each do |error|
        logger.warn "Could not create user #{user.login}: #{error}"
      end
    end
  end

  def successful_authentication(user)
    logger.info "Successful authentication for '#{user.login}' from #{request.remote_ip} at #{Time.now.utc}"
    oidc_session = OidcSession.spawn(session)
    self.logged_user = user
    oidc_session.save!
    redirect_back_or_default my_page_path
  end

end
