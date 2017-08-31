###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipb_44553.nasl 6705 2017-07-12 14:25:59Z cfischer $
#
# Invision Power Board IP.Board Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "IP.Board is a community forum implemented in PHP.

Attackers can exploit this issue to obtain sensitive information that
may aid in further attacks.

IP.Board 3.1.3 is vulnerable; other versions may be affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100882";
CPE = "cpe:/a:invision_power_services:invision_power_board";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 6705 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:25:59 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2010-11-01 13:16:04 +0100 (Mon, 01 Nov 2010)");
 script_bugtraq_id(44553);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Invision Power Board IP.Board Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44553");
 script_xref(name : "URL" , value : "http://www.invisionpower.com/");
 script_xref(name : "URL" , value : "http://community.invisionpower.com/topic/323970-ipboard-30x-31x-security-patch-released/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("invision_power_board_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("invision_power_board/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(version_in_range(version: vers, test_version: "3.1", test_version2:"3.1.3") ||
     version_in_range(version: vers, test_version: "3.0", test_version2:"3.0.5")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
