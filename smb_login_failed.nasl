###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_login_failed.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# SMB Login Failed For Authenticated Checks
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106091");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 10:44:56 +0700 (Fri, 03 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("SMB Login Failed For Authenticated Checks");

  script_tag(name:"summary", value:"It was NOT possible to login using the provided SMB
credentials. Hence authenticated checks are not enabled.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_login.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("login/SMB/failed");


  exit(0);
}
include ("smb_nt.inc");
port = get_kb_item("login/SMB/failed/port");
if (!port)
  port = kb_smb_transport();

log_message(port: port);

exit(0);

