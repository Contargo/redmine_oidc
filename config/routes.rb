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

Rails.application.routes.draw do
  get 'oidc/login', to: 'oidc#login', as: 'oidc_login'
  get 'oidc/callback', to: 'oidc#callback', as: 'oidc_callback'
  get 'oidc/logout', to: 'oidc#logout', as: 'oidc_logout'
  get 'oidc/local_logout', to: 'oidc#local_logout', as: 'oidc_local_logout'
  get 'oidc/check_session_iframe', to: 'oidc#check_session_iframe', as: 'oidc_check_session_iframe'
end
