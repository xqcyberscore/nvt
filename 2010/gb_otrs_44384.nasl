###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_44384.nasl 6705 2017-07-12 14:25:59Z cfischer $
#
# OTRS 'AgentTicketZoom' HTML Injection Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100884";
CPE = "cpe:/a:otrs:otrs";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 6705 $");
 script_tag(name:"deprecated", value:TRUE);
 script_cve_id("CVE-2010-4071");
 script_bugtraq_id(44384);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:25:59 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2010-11-01 13:16:04 +0100 (Mon, 01 Nov 2010)");
 script_name("OTRS 'AgentTicketZoom' HTML Injection Vulnerability");

tag_summary =
"This NVT has been replaced by NVT secpod_otrs_xss_vuln.nasl
(OID:1.3.6.1.4.1.25623.1.0.902352).

OTRS is prone to an HTML-injection vulnerability";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"An error exists in application which fails to properly sanitize user-supplied
input before using it in dynamically generated content.";

tag_impact =
"Successful exploits will allow attacker-supplied HTML and script
code to run in the context of the affected browser, potentially
allowing the attacker to steal cookie-based authentication
credentials or to control how the site is rendered to the user.
Other attacks are also possible.

Impact Level: Application";

tag_affected =
"Versions prior to OTRS 2.4.9 are vulnerable.";

tag_solution =
"Upgrade to higher OTRS version or Apply patch from the vendor advisory link
http://otrs.org/advisory/OSA-2010-03-en/";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44384");
 script_xref(name : "URL" , value : "http://otrs.org/");
 script_xref(name : "URL" , value : "http://otrs.org/advisory/OSA-2010-03-en/");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_otrs_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("OTRS/installed");
 exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

exit(66); ## This NVT is deprecated as addressed in secpod_otrs_xss_vuln.nasl

## Variable initialisation
port = "";
vers = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  if(version_is_less(version: vers, test_version: "2.4.9")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
