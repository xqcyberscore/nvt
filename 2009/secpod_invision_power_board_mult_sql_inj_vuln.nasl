###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_invision_power_board_mult_sql_inj_vuln.nasl 10212 2018-06-15 09:51:23Z ckuersteiner $
#
# Invision Power Board Multiple SQL Injection Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900981");
  script_version("$Revision: 10212 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 11:51:23 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3974");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("Invision Power Board Multiple SQL Injection Vulnerabilities");

  script_xref(name: "URL", value: "http://en.securitylab.ru/nvd/387879.php");
  script_xref(name: "URL", value: "http://www.vupen.com/english/advisories/2009/2413");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Secpod");
  script_family("Web application abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("invision_power_board/installed");

  script_tag(name: "impact", value: "Successful exploitation will allow attackers to access and modify the backend
database by injecting arbitrary SQL queries.");

  script_tag(name: "affected", value: "Invision Power Board version 3.0.0, 3.0.1, and 3.0.2.");

  script_tag(name: "insight", value: "The input passed into 'search_term' parameter in search.php and in 'aid'
parameter in lostpass.php is not porpperly sanitisied before being used to construct SQL queries.");

  script_tag(name: "summary", value: "The host is running Invision Power Board and is prone to multiple SQL
Injection vulnerabilities.");

  script_tag(name: "solution", value: "Apply the following patch.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!ipbPort = get_app_port(cpe:CPE))
  exit(0);

if (!ipbVer = get_app_version(cpe:CPE, port:ipbPort))
  exit(0);

if (ipbVer =~ "^3\.0\.(0|1|2)") {
  security_message(ipbPort);
  exit(0);
}

exit(99);
