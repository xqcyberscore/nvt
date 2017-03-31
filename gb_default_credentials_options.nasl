###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_default_credentials_options.nasl 5468 2017-03-02 12:10:36Z cfi $
#
# Options for Brute Force NVTs
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103697");
  script_version("$Revision: 5468 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-02 13:10:36 +0100 (Thu, 02 Mar 2017) $");
  script_tag(name:"creation_date", value:"2013-04-15 10:23:42 +0200 (Mon, 15 Apr 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Options for Brute Force NVTs");
  script_category(ACT_SETTINGS);
  script_family("Settings");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");

  script_add_preference(name:"Credentials file:", value: "", type: "file");
  script_add_preference(name:"Use only credentials listed in uploaded file:", type:"checkbox", value:"yes");

  tag_summary = "This NVT set some options for the brute force credentials checks.

  - Credentials file:

  A file containing a list of credentials. One username/password pair per line. Username and password are separated
  by ';'. Please use 'none' for empty passwords or empty usernames. If the username or the password contains a ';',
  please escape it with '\;'.

  Example:

  user;userpass

  user1;userpass1

  none;userpass2

  user3;none

  user4;pass\;word

  user5;userpass5

  - Use only credentials listed in uploaded file:

  Use only the credentials that are listed in the uploaded file. The internal default credentials are ignored.";

  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

credentials_list = script_get_preference_file_content("Credentials file:");
if(!credentials_list)exit(0);

credentials_lines = split(credentials_list, keep:0);

foreach line (credentials_lines) {

  if(line !~ "^.+;.+$") {
    log_message(data: "Invalid line " + line + " in uploaded credentials file. Scanner will not use this line.", port: 0);
    continue; 
  }  

  set_kb_item(name:"default_credentials/credentials", value: line);

}  

uploaded_credentials_only = script_get_preference("Use only credentials listed in uploaded file:");
set_kb_item(name:"default_credentials/uploaded_credentials_only", value: uploaded_credentials_only);

exit(0);
