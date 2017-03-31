##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipam_mult_vul_sep_16.nasl 4035 2016-09-12 12:23:08Z teissa $
# PHPIPAM 1.2.1 - Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

tag_insight = " PHPIPAM version 1.2.1 suffers from cross site scripting and remote SQL injection vulnerabilities..";

tag_impact = "Allows unauthorized disclosure of information; Allows unauthorized modification; Allows disruption of service .";

tag_affected = "PHPIPAM 1.2.1.";

tag_summary = "PHPIPAM is prone to multiple vulnerabilities.";

tag_solution = "Refer to vendor at http://phpipam.net";

CPE = "cpe:/a:ipam:ipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107047");
  script_version("$Revision: 4035 $");
  script_tag(name:"last_modification", value:"$Date: 2016-09-12 14:23:08 +0200 (Mon, 12 Sep 2016) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-09-12 06:40:16 +0200 (Mon, 12 Sep 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("PHPIPAM 1.2.1 - Multiple Vulnerabilities");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138603/PHPIPAM-1.2.1-Cross-Site-Scripting-SQL-Injection.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("ipam/installed");
  script_require_ports("Services/www", 80);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}
include("host_details.inc");
include("version_func.inc");


if ( !appPort = get_app_port( cpe:CPE)) appPort = 80;
if ( !appVer = get_app_version( cpe:CPE, port: appPort) ) exit(0);
if ( appVer == "1.2.1" )
{
  security_message( port:appPort);
  exit(0);
}

exit(0); 


