###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_xss_n_csrf_vuln01_may14.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# ownCloud Multiple XSS & CSRF Vulnerabilities -01 May14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:owncloud:owncloud";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804276";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2013-0307", "CVE-2013-0299", "CVE-2013-0297");
  script_bugtraq_id(58107, 58484, 58485);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-05 10:31:11 +0530 (Mon, 05 May 2014)");
  script_name("ownCloud Multiple XSS & CSRF Vulnerabilities -01 May14");

  tag_summary =
"This host is installed with ownCloud and is prone to multiple cross-site
scripting and cross-site request forgery vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- Improper validation of user-supplied input passed via 'site_name' and
'site_url' parameters to /apps/external/ajax/setsites.php script, 'Group Input'
parameter passed to the settings.php script.
- Insufficient validation of user-supplied input passed via the 'lat' and
'lng' parameters to apps/calendar/ajax/settings/guesstimezone.php, the
'timezonedetection' parameter to calendar/ajax/settings/timezonedetection.php,
admin_export parameter to apps/admin_migrate/settings.php, operation parameter to
apps/user_migrate/ajax/export.php, unspecified vectors to
apps/user_ldap/settings.php";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct request forgery
attacks and execute arbitrary script code in a user's browser.

Impact Level: Application";

 tag_affected =
"ownCloud Server before version 4.0.12 and 4.5.x before 4.5.7";

  tag_solution =
"Upgrade to ownCloud version 4.0.12 or 4.5.7 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q1/378");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-004");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-003");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ownPort = "";
ownVer = "";

## get the port
if(!ownPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get version
if(!ownVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ownPort)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:ownVer, test_version:"4.0.12")||
   version_in_range(version:ownVer, test_version:"4.5.0", test_version2:"4.5.6"))
{
  security_message(port:ownPort);
  exit(0);
}
