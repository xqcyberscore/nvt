# OpenVAS
# $Id: ssh_authorization_init.nasl 2837 2016-03-11 09:19:51Z benallard $
# Description: This script allows to set SSH credentials for target hosts.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
# Felix Wolfsteller <felix.wolfsteller@greenbone.net>
# Chandrashekhar B <bchandra@secpod.com>
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2007,2008,2009,2010,2011,2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

tag_summary = "This script allows users to enter the information
required to authorize and login via ssh protocol.

These data will be used by other tests to executed
authenticated checks.";

if(description)
{
 script_id(103591);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2012-10-24 10:55:52 +0100 (Wed, 24 Oct 2012)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("SSH Authorization");


 script_summary("Sets SSH key-based authorization, optionally on a per-target basis.");
 script_category(ACT_SETTINGS);
  script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("Copyright 2007-2012 Greenbone Networks GmbH");
 script_family("Credentials");

# Preference type to trigger client-side ssh-login selection per target
 script_add_preference(name:"Keys:", type:"sshlogin", value:"-");

# Preference to decide whether to use old-style "single" login or the "new" per-target-wise
# (deprecated: once openvas-server < 2.0.1 is not supported anymore this can be removed)
 script_add_preference(name:"Use per-target login information", type:"checkbox", value:"no");
# Following values will be used for the default case of "single" login definition for all targets
# (deprecated: once openvas-server < 2.0.1 is not supported anymore this can be removed)
 script_add_preference(name:"SSH login name:", type:"entry", value:"sshovas");
 script_add_preference(name:"SSH password (unsafe!):", type:"password", value:"");
 script_add_preference(name:"SSH public key:", type:"file", value:"");
 script_add_preference(name:"SSH private key:", type:"file", value:"");
 script_add_preference(name:"SSH key passphrase:", type:"password", value:"");

 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

use_new = script_get_preference("Use per-target login information");

if(use_new == "no")
{
  # Old-style "single" login for all targets
  ssh_login_name = script_get_preference("SSH login name:");
  ssh_password = script_get_preference("SSH password (unsafe!):");
  ssh_public_key = script_get_preference_file_content("SSH public key:");
  ssh_private_key = script_get_preference_file_content("SSH private key:");
  ssh_key_passphrase = script_get_preference("SSH key passphrase:");

  if (ssh_login_name) set_kb_item(name: "Secret/SSH/login", value: ssh_login_name);
  if (ssh_password) set_kb_item(name:"Secret/SSH/password", value:ssh_password);
  if (ssh_public_key) set_kb_item(name: "Secret/SSH/publickey", value: ssh_public_key);
  if (ssh_private_key) set_kb_item(name: "Secret/SSH/privatekey", value: ssh_private_key);
  if (ssh_key_passphrase) set_kb_item(name: "Secret/SSH/passphrase", value: ssh_key_passphrase);
}

exit(0);
