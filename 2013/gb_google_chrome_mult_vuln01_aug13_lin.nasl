###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_aug13_lin.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 August13 (Linux)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: System/Application";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803878");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-2887", "CVE-2013-2900", "CVE-2013-2901", "CVE-2013-2902",
                "CVE-2013-2903", "CVE-2013-2904", "CVE-2013-2905");
  script_bugtraq_id(61885, 61887, 61891, 61886, 61888, 61889, 61890);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-26 13:01:25 +0530 (Mon, 26 Aug 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 August13 (Linux)");

  tag_summary =
"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- Some unspecified errors exist.
- An error exists when handling file paths.
- An integer overflow error exists within ANGLE.
- Insecure permissions when creating certain shared memory files.
- Use-after-free error exists within XSLT, media element and document parsing.";

  tag_impact =
"Successful exploitation will allow attackers to disclose potentially sensitive
information, compromise a user's system and other attacks may also be possible.";

  tag_affected =
"Google Chrome version prior to 29.0.1547.57 on Linux.";

  tag_solution =
"Upgrade to version 29.0.1547.57 or later,
For updates refer to http://www.google.com/chrome";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54479");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/08/stable-channel-update.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 29.0.1547.57
if(version_is_less(version:chromeVer, test_version:"29.0.1547.57"))
{
  security_message(0);
  exit(0);
}
