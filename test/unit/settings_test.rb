require File.expand_path('../../test_helper', __FILE__)

require 'redmine_oidc/settings'

class RedmineOidcSettingsTest < ActiveSupport::TestCase

  test 'Settings are valid if OIDC is disabled' do
    with_oidc_settings({ 'enabled' => false }) do
      settings = RedmineOidc::Settings.current
      assert settings.valid?
    end
  end

  test 'Settings are invalid if missing issuer URL' do
    with_oidc_settings({ 'enabled' => true }) do
      settings = RedmineOidc::Settings.current
      assert settings.invalid?
      assert_not_nil settings.errors[:issuer_url]
    end
  end


  test 'Settings are invalid if missing client ID/secret' do
    with_oidc_settings({'enabled' => true,'issuer_url' => 'https://login.example.com'}) do
      settings = RedmineOidc::Settings.current
      assert settings.invalid?
      assert_not_nil settings.errors[:client_id]
      assert_not_nil settings.errors[:client_secret]
    end
  end

  test 'Settings are invalid if missing scope' do
    with_oidc_settings({ 'enabled' => true, 'issuer_url' => 'https://login.example.com', 'client_id' => 'client', 'client_secret' => 'secret' }) do
      settings = RedmineOidc::Settings.current
      assert settings.invalid?
      assert_not_nil settings.errors[:scope]
    end
  end

  test 'Settings are valid if complete' do
    with_oidc_settings({ 'enabled' => true, 'issuer_url' => 'https://login.example.com', 'client_id' => 'client', 'client_secret' => 'secret', 'scope' => 'openid' }) do
      settings = RedmineOidc::Settings.current
      assert settings.valid?
      assert settings.errors.empty?
    end
  end
end
