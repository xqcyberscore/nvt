###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_49251.nasl 7006 2017-08-25 11:51:20Z teissa $
#
# OTRS 'AdminPackageManager.pm' Local File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103216";
CPE = "cpe:/a:otrs:otrs";


if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 7006 $");
 script_cve_id("CVE-2011-2746");
 script_bugtraq_id(49251);
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2017-08-25 13:51:20 +0200 (Fri, 25 Aug 2017) $");
 script_tag(name:"creation_date", value:"2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)");
 script_name("OTRS 'AdminPackageManager.pm' Local File Disclosure Vulnerability");

tag_summary =
"OTRS is prone to a local file-disclosure vulnerability";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"An error exists in application which fails to adequately validate
user-supplied input.";

tag_impact =
"Exploiting this vulnerability would allow an attacker to obtain potentially
sensitive information from local files on computers running the vulnerable
application. This may aid in further attacks.

Impact Level: Application";

tag_affected =
"Open Ticket Request System (OTRS) version 2.4.x before 2.4.11 and 3.x before 3.0.8";

tag_solution =
"Updates are available. Please see the references for more information.";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49251");
  script_xref(name : "URL" , value : "http://otrs.org/");
  script_xref(name : "URL" , value : "http://otrs.org/advisory/OSA-2011-03-en/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

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
  if(version_in_range(version: vers, test_version:"2.4", test_version2:"2.4.10") ||
     version_in_range(version: vers, test_version:"3.0", test_version2:"3.0.7"))
  {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
