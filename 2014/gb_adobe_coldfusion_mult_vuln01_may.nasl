###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_coldfusion_mult_vuln01_may.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Adobe ColdFusion Multiple Vulnerabilities-01 May-2014
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804442";
CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2013-5326", "CVE-2013-5328");
  script_bugtraq_id(63681, 63682);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-06 13:50:21 +0530 (Tue, 06 May 2014)");
  script_name("Adobe ColdFusion Multiple Vulnerabilities-01 May-2014");

  tag_summary =
"This host is running Adobe ColdFusion and is prone to multiple
vulnerabilities";

  tag_vuldetect =
"Get the installed version of Adobe ColdFusion with the help of
detect NVT and check the version is vulnerable or not.";

  tag_insight =
"Multiple flaws are  due to,
- Certain unspecified input is not properly sanitised before being
  returned to the user. This can be exploited to execute arbitrary HTML
  and script code in a user's browser session in context of an affected
  site.
- An unspecified error can be exploited to gain unauthorised read access.
  No further information is currently available.";

  tag_impact =
"Successful exploitation will allow attackers to conduct cross-site scripting
attacks and bypass certain security restrictions.

Impact Level: Application";

  tag_affected =
"Adobe ColdFusion 10 before Update 12";

  tag_solution =
"Upgrade to Adobe ColdFusion 10 Update 12 or later,
https://www.adobe.com/cfusion/tdrc/index.cfm?product=coldfusion";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/295276");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/88739");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-27.html");
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

if(version_in_range(version:smgVer, test_version:"10.0", test_version2:"10.0.12.286679"))
{
  security_message(port:smgPort);
  exit(0);
}
