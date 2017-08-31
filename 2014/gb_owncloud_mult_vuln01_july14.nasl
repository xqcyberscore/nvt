###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_vuln01_july14.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# ownCloud Multiple Vulnerabilities-01 July14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804658");
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2012-5056", "CVE-2012-5057", "CVE-2012-5336");
  script_bugtraq_id(68295, 68305);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-07-03 12:50:12 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud Multiple Vulnerabilities-01 July14");

  tag_summary =
"This host is installed with ownCloud and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to an,
- Input passed to 'apps/files_odfviewer/src/webodf/webodf/flashput/PUT.swf'
  script via 'readyCallback' parameter is not sanitized before returning it to
  users.
- Input passed to 'lib/db.php' script via malformed query is not sanitized
  before returning it to users.
- Input passed to 'apps/gallery/templates/index.php' script via 'root'
  parameter is not sanitized before returning it to users.
- Application does not validate the URL path upon submission to the 'index.php'
  script.
- Improper validation of input passed to 'lib/base.php' script via
  'user_id session' variable.";

  tag_impact =
"Successful exploitation will allow remote attackers to gain access to
arbitrary user files, insert arbitrary HTTP headers and execute arbitrary
script code in a user's browser session within the trust relationship
between their browser and the server.

Impact Level: Application";

  tag_affected =
"ownCloud Server 4.0.x before 4.0.8";

  tag_solution =
"Upgrade to ownCloud version 4.0.8 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/CVE-2012-5336");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/CVE-2012-5057");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/CVE-2012-5056");
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
if(version_in_range(version:ownVer, test_version:"4.0.0", test_version2:"4.0.7"))
{
  security_message(port:ownPort);
  exit(0);
}
