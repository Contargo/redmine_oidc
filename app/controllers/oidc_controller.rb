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
    redirect_to OidcSession.spawn(session).authorization_endpoint(redirect_uri: oidc_callback_url)
  end

  def callback
    oidc_session = OidcSession.spawn(session)
    oidc_session.update!(params)
    oidc_session.acquire!
    oidc_session.authorized? ? login_user : lock_user
  rescue Exception => exception
    logger.error "#{exception.class}: #{exception.message}"
    render 'callback', :status => :loop_detected
  end

  def logout
    oidc_session = OidcSession.spawn(session)
    if oidc_session.complete?
      oidc_session.destroy!
      logout_user
      reset_session
      redirect_to oidc_session.end_session_endpoint(post_logout_redirect_uri: oidc_local_logout_url)
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

  def lock_user
    user = User.find_by_oidc_identifier(OidcSession.spawn(session).oidc_identifier)
    user.lock! unless user.nil?
    render 'lock_user', :status => :unauthorized
  end

  def login_user
    @oidc_session = OidcSession.spawn(session)
    user = User.find_by_oidc_identifier(@oidc_session.oidc_identifier)
    if user.nil?
      create_user
    else
      update_user(user)
    end
  end

  def create_user
    user = User.create(@oidc_session.user_attributes)
    user.activate
    user.random_password
    user.last_login_on = Time.now
    user.save ? successful_login(user) : unsuccessful_login(user)
  end

  def update_user(user)
    user.update(@oidc_session.user_attributes)
    user.activate
    user.update_last_login_on!
    if session[:back_url]
      params[:back_url] = session[:back_url]
      session[:back_url] = nil
    end
    user.save ? successful_login(user) : unsuccessful_login(user)
  end

  def successful_login(user)
    logger.info "Successful authentication for '#{user.login}' from #{request.remote_ip} at #{Time.now.utc}"
    oidc_session = OidcSession.spawn(session)
    self.logged_user = user
    oidc_session.save!
    redirect_back_or_default my_page_path
  end

  def unsuccessful_login(user)
    user.errors.full_messages.each do |error|
      logger.warn "Could not create user #{user.login}: #{error}"
    end
  end

end
