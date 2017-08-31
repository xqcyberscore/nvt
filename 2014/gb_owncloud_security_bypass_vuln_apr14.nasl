###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_security_bypass_vuln_apr14.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# ownCloud Local Filesystem Mounting Security Bypass Vulnerability Apr14
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804363";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2014-2585");
  script_bugtraq_id(66451);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-04 18:54:56 +0530 (Fri, 04 Apr 2014)");
  script_name("ownCloud Local Filesystem Mounting Security Bypass Vulnerability Apr14");

  tag_summary =
"This host is installed with ownCloud and is prone to security bypass
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to the server failing to properly sanitize mount
configurations.";

  tag_impact =
"Successful exploitation will allow remote attacker to mount the local
filesystem and gain access to the information contained within it.

Impact Level: Application";

 tag_affected =
"ownCloud Server version 5.x before 5.0.15 and 6.x before 6.0.2";

  tag_solution =
"Upgrade to ownCloud version 5.0.15 or 6.0.2 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57283");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2014-008");
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

if(version_in_range(version:ownVer, test_version:"5.0.0", test_version2:"5.0.14")||
   version_in_range(version:ownVer, test_version:"6.0", test_version2:"6.0.1"))
{
  security_message(port:ownPort);
  exit(0);
}
