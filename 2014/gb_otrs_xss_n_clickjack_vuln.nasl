###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_xss_n_clickjack_vuln.nasl 6756 2017-07-18 13:31:14Z cfischer $
#
# OTRS Help Desk Cross-Site Scripting and Clickjacking Vulnerabilities
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804418";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6756 $");
  script_cve_id("CVE-2014-2553", "CVE-2014-2554");
  script_bugtraq_id(66569, 66567);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 15:31:14 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-07 15:00:42 +0530 (Mon, 07 Apr 2014)");
  script_name("OTRS Help Desk Cross-Site Scripting and Clickjacking Vulnerabilities");

tag_summary =
"This host is running OTRS (Open Ticket Request System) and is prone to
cross-site scripting and clickjacking vulnerabilities.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"- Certain input related to dynamic fields is not properly sanitised before
   being returned to the user.
 - The application allows users to perform certain actions via HTTP requests
   via iframes without performing any validity checks to verify the requests.";

tag_impact =
"Successful exploitation will allow attackers to conduct cross-site scripting
and clickjacking attacks.

Impact Level: Application";

tag_affected =
"Open Ticket Request System (OTRS) version 3.1.x before 3.1.21,
3.2.x before 3.2.16, and 3.3.x before 3.3.6";

tag_solution =
"Upgrade to OTRS version 3.1.21 or 3.2.16 or 3.3.6 or later,
For updates refer to http://www.otrs.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57616");
  script_xref(name : "URL" , value : "http://bugs.otrs.org/show_bug.cgi?id=10361");
  script_xref(name : "URL" , value : "http://bugs.otrs.org/show_bug.cgi?id=10374");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");

  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable initialization
otrsport = "";
vers = "";

## Get Application HTTP Port
if(!otrsport = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:otrsport))
{
  if(version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.20") ||
     version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.15") ||
     version_in_range(version:vers, test_version:"3.3.0", test_version2:"3.3.5"))
  {
    security_message(port:otrsport);
    exit(0);
  }
}
