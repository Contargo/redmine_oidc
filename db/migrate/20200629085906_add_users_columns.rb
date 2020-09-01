class AddUsersColumns < ActiveRecord::Migration[5.2]
  def change
    add_column :users, :oidc_identifier, :string
    add_column :users, :avatar_url, :string
  end
end
