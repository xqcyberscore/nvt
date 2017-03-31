###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_php_code_exec_vuln_apr14.nasl 3554 2016-06-20 07:41:15Z benallard $
#
# ownCloud PHP Remote Code Execution Vulnerabilities Apr14
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804364";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3554 $");
  script_cve_id("CVE-2013-7344", "CVE-2013-0303");
  script_bugtraq_id(58109);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 09:41:15 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-04-07 10:17:33 +0530 (Mon, 07 Apr 2014)");
  script_name("ownCloud PHP Remote Code Execution Vulnerabilities Apr14");

  tag_summary =
"This host is installed with ownCloud and is prone to remote code execution
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws exist due to,
- Unspecified input passed to core/ajax/translations.php is not properly
  sanitized before being used.
- Unspecified input passed to core/settings.php is not properly sanitized
  before being used.";

  tag_impact =
"Successful exploitation will allow remote attacker to mount the local
filesystem and gain access to the information contained within it.

Impact Level: Application";

 tag_affected =
"ownCloud Server version 4.5.x before 4.5.6 and 4.0.x before 4.0.12";

  tag_solution =
"Upgrade to ownCloud version 4.5.6 or 4.0.12 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/52303");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q1/378");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-006");
  script_summary("Check the version ownCloud vulnerable or not");
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

## Check the port status
if(!get_port_state(ownPort)){
  exit(0);
}

## Get the location
if(!ownVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ownPort)){
  exit(0);
}

if(version_in_range(version:ownVer, test_version:"4.5.0", test_version2:"4.5.5")||
  version_in_range(version:ownVer, test_version:"4.0.0", test_version2:"4.0.11"))
{
  security_message(port:ownPort);
  exit(0);
}
