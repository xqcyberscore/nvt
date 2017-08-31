###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_43264.nasl 6705 2017-07-12 14:25:59Z cfischer $
#
# OTRS Core System Multiple Cross-Site Scripting and Denial of Service Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100821";
CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6705 $");
  script_cve_id("CVE-2010-2080", "CVE-2010-3476");
  script_bugtraq_id(43264);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:25:59 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");
  script_name("OTRS Core System Multiple Cross-Site Scripting and Denial of Service Vulnerabilities");

tag_summary =
"OTRS is prone to multiple cross-site scripting vulnerabilities and a
denial-of-service vulnerability";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"An error exists in application which fails to properly handle
user-supplied input.";

tag_impact =
"An attacker may leverage these issues to cause denial-of-service
conditions or to execute arbitrary script code in the browser of an
unsuspecting user in the context of the affected site.

Impact Level: Application";

tag_affected =
"OTRS versions prior to 2.3.6 and 2.4.8 are vulnerable.";

tag_solution =
"Upgrade to OTRS (Open Ticket Request System) higher than 2.3.6 or 2.4.8
or later, For updates refer to http://www.otrs.com/en/ or Apply patch from the
vendor advisory link http://otrs.org/advisory/OSA-2010-02-en/";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43264");
  script_xref(name : "URL" , value : "http://otrs.org/");
  script_xref(name : "URL" , value : "http://otrs.org/advisory/OSA-2010-02-en/");
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
  if(vers =~ "^2\.4") {
    if(version_is_less(version: vers, test_version: "2.4.8")) {
        security_message(port:port);
        exit(0);
    }
  }

  if(vers =~ "^2\.3") {
    if(version_is_less(version: vers, test_version: "2.3.6")) {
        security_message(port:port);
        exit(0);
    }
  }
}

exit(0);
