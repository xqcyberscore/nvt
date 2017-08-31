###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_vuln02_july14.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# ownCloud Multiple Vulnerabilities-02 July14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804657");
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2014-2051", "CVE-2014-2053", "CVE-2014-2054", "CVE-2014-2055",
                "CVE-2014-2056");
  script_bugtraq_id(66220, 66225, 66172, 66226, 66218);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-07-03 12:20:12 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud Multiple Vulnerabilities-02 July14");

  tag_summary =
"This host is installed with ownCloud and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws exist due to,
- The program fails to properly sanitize LDAP queries.
- An incorrectly configured XML parser accepting XML external entities from an
  untrusted source";

  tag_impact =
"Successful exploitation will allow remote attackers to gain information about
existing LDAP users and potentially modify the login query, read arbitrary files,
cause a denial of service, or possibly have other impact via an XML External
Entity (XXE) attack.

Impact Level: Application";

  tag_affected =
"ownCloud Server 5.0.x before 5.0.15 and 6.0.x before 6.0.2";

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
  script_xref(name : "URL" , value : "http://owncloud.org/about/security/advisories/oC-SA-2014-005");
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
if(version_in_range(version:ownVer, test_version:"5.0.0", test_version2:"5.0.14")||
   version_in_range(version:ownVer, test_version:"6.0.0", test_version2:"6.0.1"))
{
  security_message(port:ownPort);
  exit(0);
}
