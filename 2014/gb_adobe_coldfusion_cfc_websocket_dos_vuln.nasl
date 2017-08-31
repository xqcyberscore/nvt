###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_coldfusion_cfc_websocket_dos_vuln.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# Adobe ColdFusion Components (CFC) Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804443";
CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6692 $");
  script_cve_id("CVE-2013-3350");
  script_bugtraq_id(61042);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-06 15:14:38 +0530 (Tue, 06 May 2014)");
  script_name("Adobe ColdFusion Components (CFC) Denial Of Service Vulnerability");

  tag_summary =
"This host is running Adobe ColdFusion and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version of Adobe ColdFusion with the help of detect NVT and
check the version is vulnerable or not.";

  tag_insight =
"The flaw is due to an error in ColdFusion Components (CFC) public methods
which can be accessed via WebSockets.";

  tag_impact =
"Successful exploitation will allow attackers to cause denial of service
conditions.

Impact Level: Application";

  tag_affected =
"Adobe ColdFusion 10 before Update 11";

  tag_solution =
"Upgrade to Adobe ColdFusion 10 Update 11 or later,
https://www.adobe.com/cfusion/tdrc/index.cfm?product=coldfusion";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028757");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-19.html");
  script_xref(name : "URL" , value : "http://blogs.coldfusion.com/post.cfm/coldfusion-10-websocket-vulnerebility");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("coldfusion/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialization
smgPort = "";
smgVer = "";

## Get Application HTTP Port
if(!smgPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
smgVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:smgPort);
if(!smgVer || "unknown" >< smgVer){
  exit(0);
}

if(version_in_range(version:smgVer, test_version:"10.0", test_version2:"10.0.11.285436"))
{
  security_message(port:smgPort);
  exit(0);
}
