# OpenID Connect Authentication for Redmine
# Copyright (C) 2020 Contargo GmbH & Co. KG
#
module RedmineOidc
  def self.settings
    RedmineOidc::Settings.current
  end
end
