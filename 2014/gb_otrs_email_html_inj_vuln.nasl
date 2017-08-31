###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_email_html_inj_vuln.nasl 6756 2017-07-18 13:31:14Z cfischer $
#
# OTRS Email HTML Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804243";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6756 $");
  script_cve_id("CVE-2014-1695");
  script_bugtraq_id(65844);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 15:31:14 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-04 17:31:09 +0530 (Tue, 04 Mar 2014)");
  script_name("OTRS Email HTML Injection Vulnerability");

tag_summary =
"This host is running OTRS (Open Ticket Request System) and is prone to html
injection vulnerability.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"An error exists in OTRS core system which fails to properly sanitize
user-supplied input before using it in dynamically generated content";

tag_impact =
"Successful exploitation will allow attackers to steal the victim's
cookie-based authentication credentials.

Impact Level: Application";

tag_affected =
"Open Ticket Request System (OTRS) version 3.1.x before 3.1.20, 3.2.x before 3.2.15,
and 3.3.x before 3.3.5";

tag_solution =
"Upgrade to OTRS version 3.1.20 or 3.2.15 or 3.3.5 or later,
For updates refer to http://www.otrs.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57018");
  script_xref(name : "URL" , value : "https://www.otrs.com/security-advisory-2014-03-xss-issue");
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
  if(version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.19") ||
     version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.14") ||
     version_in_range(version:vers, test_version:"3.3.0", test_version2:"3.3.4"))
  {
    security_message(port:otrsport);
    exit(0);
  }
}
