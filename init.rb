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

require 'redmine_oidc'

Redmine::Plugin.register :redmine_oidc do
  name 'Redmine OpenId Connect plugin'
  author 'Contargo GmbH & Co. KG'
  description 'Add login with OpenId Connect as another login option'
  version '1.1.0'
  url 'https://github.com/Contargo/redmine_oidc'
  author_url 'https://contargo.net'
  settings :default => {:enabled => false},
           :partial => 'settings/redmine_oidc'
end
