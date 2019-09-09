###############################################################################
# OpenVAS Vulnerability Test
#
# IPMI Anonymous Login Enabled
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103836");
  script_version("2019-09-06T14:17:49+0000");
  script_tag(name:"last_modification", value:"2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"creation_date", value:"2013-11-26 12:03:03 +0100 (Tue, 26 Nov 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IPMI Anonymous Login Enabled");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_ipmi_detect.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/anonymous_login");

  script_tag(name:"solution", value:"Disable anonymous logins.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"summary", value:"The remote IPMI service accepts anonymous logins.");

  exit(0);
}

port = get_kb_item("Services/udp/ipmi");
if(!port)exit(0);

if(get_kb_item("ipmi/anonymous_login")) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);

