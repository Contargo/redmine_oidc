module RedmineOidc
  def self.settings() Setting[:plugin_redmine_oidc].stringify_keys end
end
