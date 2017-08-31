###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_calendar_calid_priv_esc_vuln.nasl 6637 2017-07-10 09:58:13Z teissa $
#
# ownCloud 'calid' Parameter privilege Escalation Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804656");
  script_version("$Revision: 6637 $");
  script_cve_id("CVE-2013-0304");
  script_bugtraq_id(58111);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-07-03 11:57:36 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud 'calid' Parameter privilege Escalation Vulnerability");

  tag_summary =
"This host is installed with ownCloud and is prone to privilege escalation
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw exists due to improper verification of input passed via the
'calid' parameter passed to /apps/calendar/export.php when checking for
ownership.";

  tag_impact =
"Successful exploitation will allow remote attackers to gain privilege and
download calendars of other users.

Impact Level: Application";

  tag_affected =
"ownCloud Server 4.5.x before 4.5.7";

  tag_solution =
"Upgrade to ownCloud version 4.5.7 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/52303");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q1/378");
  script_xref(name : "URL" , value : "http://owncloud.org/security/advisory/?id=oC-SA-2013-007");
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
if(!ownPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get version
if(!ownVer = get_app_version(cpe:CPE, port:ownPort)){
  exit(0);
}

## Grep for vulnerable version
if(version_in_range(version:ownVer, test_version:"4.5.0", test_version2:"4.5.6"))
{
  security_message(port:ownPort);
  exit(0);
}
