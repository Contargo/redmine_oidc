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
    if !User.current.logged?
      redirect_to OidcSession.spawn(session).authorization_endpoint(
                    redirect_uri: oidc_callback_url(back_url: params[:back_url]))
    else
      redirect_to my_page_path
    end
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

end
