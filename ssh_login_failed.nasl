###############################################################################
# OpenVAS Vulnerability Test
# $Id: ssh_login_failed.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# SSH Login Failed For Authenticated Checks
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105936");
  script_version("$Revision: 6065 $");
  script_tag(name : "last_modification", value : "$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name : "creation_date", value : "2014-12-16 10:58:24 +0700 (Tue, 16 Dec 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name : "cvss_base_vector", value : "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("SSH Login Failed For Authenticated Checks");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");

  script_dependencies("ssh_authorization.nasl");
  script_mandatory_keys("login/SSH/failed");

  script_tag(name : "summary", value : "It was NOT possible to login using the provided SSH
  credentials. Hence authenticated checks are not enabled.");

  script_tag(name : "solution", value : "Recheck the SSH credentials for authenticated checks.");
  exit(0);
}

port = get_preference("auth_port_ssh");
if (!port)
  port = get_kb_item("Services/ssh");

log_message(port:port);

exit(0);
