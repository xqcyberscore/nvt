###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln02_nov13_lin.nasl 33239 2013-11-25 14:00:39Z nov$
#
# Google Chrome Multiple Vulnerabilities-02 Nov2013 (Linux)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803968";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6115 $");
  script_cve_id("CVE-2013-6802", "CVE-2013-6632");
  script_bugtraq_id(63729, 63727);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-11-25 14:00:39 +0530 (Mon, 25 Nov 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-02 Nov2013 (Linux)");

  tag_summary =
"This host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version of Google Chrome and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- Unspecified security-bypass vulnerability in sandbox restrictions
- Unspecified memory-corruption vulnerabilities";

  tag_impact =
"Successful exploitation will allow remote attackers to cause a denial of
service condition, bypass sandbox protection and execute arbitrary code or
possibly have other impact via unknown vectors.

Impact Level: System/Application";

  tag_affected =
"Google Chrome version prior to 31.0.1650.57 on Linux";

  tag_solution =
"Upgrade to Google Chrome version 31.0.1650.57 or later.
For updates refer to http://www.google.com/chrome";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/11/stable-channel-update_14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
my_app_ver = "";

## Get version
if(!my_app_ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:my_app_ver, test_version:"31.0.1650.57"))
{
  security_message(0);
  exit(0);
}
