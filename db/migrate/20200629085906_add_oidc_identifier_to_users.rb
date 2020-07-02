class AddOidcIdentifierToUsers < ActiveRecord::Migration[5.2]
  def change
    add_column :users, :oidc_identifier, :string
  end
end
