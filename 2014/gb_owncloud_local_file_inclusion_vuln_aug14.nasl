###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_local_file_inclusion_vuln_aug14.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# ownCloud Local File Inclusion Vulnerability -01 Aug14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804821");
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2014-4929");
  script_bugtraq_id(68975);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-08-25 21:35:23 +0530 (Mon, 25 Aug 2014)");
  script_name("ownCloud Local File Inclusion Vulnerability -01 Aug14");

  tag_summary =
"This host is installed with ownCloud and is prone to local file inclusion
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw exists due to the Routing component not properly sanitizing
user-supplied input to the 'filename' parameter in a require_once statement.";

  tag_impact =
"Successful exploitation will allow remote attackers to reinstall the instance
overwriting the existing configuration or execute arbitrary PHP code or disclose
the contents of any file on the system.

Impact Level: System/Application";

  tag_affected =
"ownCloud Server 5.0.x before version 5.0.17, 6.0.x before version 6.0.4";

  tag_solution =
"Upgrade to ownCloud version 5.0.17 or 6.0.4 or later.
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://owncloud.org/changelog/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/59543");
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

if(ownVer =~ "^(5|6)")

## Grep for vulnerable version
if(version_in_range(version:ownVer, test_version:"5.0.0", test_version2:"5.0.16")||
   version_in_range(version:ownVer, test_version:"6.0.0", test_version2:"6.0.3"))
{
  security_message(port:ownPort);
  exit(0);
}
