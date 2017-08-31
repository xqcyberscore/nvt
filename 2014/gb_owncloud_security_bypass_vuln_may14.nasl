###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_security_bypass_vuln_may14.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# ownCloud 'contacts' Security Bypass Vulnerability - May14
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804281";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2013-1963");
  script_bugtraq_id(59319);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-05 15:00:11 +0530 (Mon, 05 May 2014)");
  script_name("ownCloud 'contacts' Security Bypass Vulnerability - May14");

  tag_summary =
"This host is installed with ownCloud and is prone to security bypass
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to the Contact application failing to properly check the
ownership of a single contact.";

  tag_impact =
"Successful exploitation will allow remote attackers to bypass security
restrictions and download contacts of arbitrary users.

Impact Level: Application";

 tag_affected =
"ownCloud Server before version 4.5.10 and 5.x before version 5.0.5";

  tag_solution =
"Upgrade to ownCloud version 4.5.10 or 5.0.5 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q2/133");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-018");
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
if(version_is_less(version:ownVer, test_version:"4.5.10")||
   version_in_range(version:ownVer, test_version:"5.0.0", test_version2:"5.0.4"))
{
  security_message(port:ownPort);
  exit(0);
}
