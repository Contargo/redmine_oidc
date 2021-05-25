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

require File.expand_path('../../test_helper', __FILE__)

require 'redmine_oidc/settings'

class RedmineOidcSettingsTest < ActiveSupport::TestCase

  test 'Settings are valid if OIDC is disabled' do
    with_oidc_settings({'enabled' => false}) do
      settings = RedmineOidc::Settings.current
      assert settings.valid?
    end
  end

  test 'Settings are invalid if missing issuer URL' do
    with_oidc_settings({'enabled' => true}) do
      settings = RedmineOidc::Settings.current
      assert settings.invalid?
      assert_not_nil settings.errors[:issuer_url]
    end
  end

  test 'Settings are invalid if missing client ID/secret' do
    with_oidc_settings({'enabled' => true,
                        'issuer_url' => 'https://login.example.com'}) do
      settings = RedmineOidc::Settings.current
      assert settings.invalid?
      assert_not_nil settings.errors[:client_id]
      assert_not_nil settings.errors[:client_secret]
    end
  end

  test 'Settings are invalid if missing scope' do
    with_oidc_settings({'enabled' => true,
                        'issuer_url' => 'https://login.example.com',
                        'client_id' => 'client',
                        'client_secret' =>
                        'secret' }) do
      settings = RedmineOidc::Settings.current
      assert settings.invalid?
      assert_not_nil settings.errors[:scope]
    end
  end

  test 'Settings are valid if complete' do
    with_oidc_settings({'enabled' => true,
                        'issuer_url' =>
                        'https://login.example.com',
                        'client_id' => 'client',
                        'client_secret' => 'secret',
                        'scope' => 'openid',
                        'unique_id_claim' => 'sub',
                        'roles_claim' => 'roles',
                        'access_roles' => 'ROLES/ADMIN,ROLES/USER',
                        'admin_role' => 'ROLES/ADMIN'}) do
      settings = RedmineOidc::Settings.current
      assert settings.valid?
      assert settings.errors.empty?
    end
  end
end
