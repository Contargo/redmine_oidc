# Load the Redmine helper
require File.expand_path(File.dirname(__FILE__) + '/../../../test/test_helper')

module RedmineOidc
  module TestHelper
    def with_oidc_settings(options, &block)
      Setting.stubs(:plugin_redmine_oidc).returns(options)
      yield
    ensure
      Settings.unstub(:plugin_redmine_oidc)
    end
  end
end

include RedmineOidc::TestHelper
