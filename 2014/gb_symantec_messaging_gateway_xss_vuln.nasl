###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_xss_vuln.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# Symantec Messaging Gateway 'displayTab' Cross-Site Scripting Vulnerability
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804440";
CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6692 $");
  script_cve_id("CVE-2014-1648");
  script_bugtraq_id(66966);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-02 11:16:59 +0530 (Fri, 02 May 2014)");
  script_name("Symantec Messaging Gateway 'displayTab' Cross-Site Scripting Vulnerability");

  tag_summary =
"This host is running Symantec Messaging Gateway and is prone to cross-site
scripting vulnerability.";

  tag_vuldetect =
"Get the installed version of Symantec Messaging Gateway with the help of
detect NVT and check the version is vulnerable or not.";

  tag_insight =
"The flaw is due to input passed via the 'displayTab' GET parameter to
/brightmail/setting/compliance/DlpConnectFlow$view.flo is not properly
sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary HTML
and script code in a user's browser session in context of an affected site.

Impact Level: Application";

  tag_affected =
"Symantec Messaging Gateway 10.x before 10.5.2";

  tag_solution =
"Upgrade to Symantec Messaging Gateway 10.5.2 or later,
For updates refer to http://www.symantec.com/messaging-gateway";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/58047");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126264/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Apr/256");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
  script_mandatory_keys("/Symantec/Messaging/Gateway/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialization
smgVer = "";

## Get application version
smgVer = get_app_version(cpe:CPE, nofork:TRUE);
if(!smgVer){
  exit(0);
}

if(version_in_range(version:smgVer, test_version:"10.0", test_version2:"10.5.1"))
{
  report = report_fixed_ver(  installed_version:smgVer, fixed_version:"10.5.2" );
  security_message(port:0, data:report);
  exit(0);
}
