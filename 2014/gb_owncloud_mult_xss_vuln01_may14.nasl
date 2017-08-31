###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_xss_vuln01_may14.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# ownCloud Multiple Cross Site Scripting Vulnerabilities -01 May14
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804279";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6735 $");
  script_cve_id("CVE-2013-1822");
  script_bugtraq_id(58482);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-05 13:20:11 +0530 (Mon, 05 May 2014)");
  script_name("ownCloud Multiple Cross Site Scripting Vulnerabilities -01 May14");

  tag_summary =
"This host is installed with ownCloud and is prone to multiple cross-site
scripting vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws exists due to insufficient validation of user-supplied input
passed via the 'quota' POST parameter to setquota.php within
/core/settings/ajax, 'group' parameter passed to the settings.php script and
'shareWith' parameter passed to the core/js/share.js script.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
script code in a user's browser within the trust relationship between their
browser and the server.

Impact Level: Application";

  tag_affected =
"ownCloud Server 4.5.x before version 4.5.8";

  tag_solution =
"Upgrade to ownCloud version 4.5.8 or later,
For updates refer to http://owncloud.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q1/652");
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2013-008");
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
if(version_in_range(version:ownVer, test_version:"4.5.0", test_version2:"4.5.7"))
{
  security_message(port:ownPort);
  exit(0);
}
