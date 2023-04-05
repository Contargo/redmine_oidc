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

require 'openid_connect'

class OidcController < ApplicationController

  skip_before_action :check_if_login_required

  def login
    if params[:reauth] || !User.current.logged?
      # max_age 0 forces the OIDC provider to reauthenticate the user and add
      # the auth_time claim to the response.
      redirect_to OidcSession.spawn(session).authorization_endpoint(
                    redirect_uri: oidc_callback_url(back_url: params[:back_url]),
                    max_age: params[:reauth] ? 0 : nil)
    else
      redirect_to my_page_path
    end
  end

  def callback
    oidc_session = OidcSession.spawn(session)
    oidc_session.update!(params)
    oidc_session.acquire!

    if session.has_key?(:oidc_sudo_deferred) && User.current.logged?
      perform_sudo_action
    elsif oidc_session.authorized?
      login_user
    else
      lock_user
    end
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

  def check_session_iframe
    @oidc_session = OidcSession.spawn(session)
    render layout: false
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

  def perform_sudo_action
    logger.info "Successful reauthentication for '#{User.current.login}' from #{request.remote_ip} at #{Time.now.utc}"

    back_url = validate_back_url(params[:back_url].to_s)
    action = session.delete(:oidc_sudo_deferred)

    if back_url && action && action[:back_url] == params[:back_url]
      if action[:options][:method] == :get
        redirect_to(back_url)
      else
        repost(back_url, params: action[:params], options: action[:options])
      end
    else
      redirect_to(my_page_path)
    end
  end

end
