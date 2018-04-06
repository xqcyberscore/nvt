###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2016-87_2016-87_macosx.nasl 9341 2018-04-06 05:27:04Z cfischer $
#
# Mozilla Firefox Security Updates( mfsa_2016-87_2016-87 )-MAC OS X
#
# Authors:
# kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809391");
  script_version("$Revision: 9341 $");
  script_cve_id("CVE-2016-5287", "CVE-2016-5288");
  script_bugtraq_id(93810);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 07:27:04 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-10-21 15:25:13 +0530 (Fri, 21 Oct 2016)");
  script_name("Mozilla Firefox Security Updates( mfsa_2016-87_2016-87 )-MAC OS X");

  script_tag(name: "summary" , value:"This host is installed with 
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,
  - Crash in nsTArray_base&lt;T&gt;::SwapArrayElements.
  - Web content can read cache entries");

  script_tag(name: "impact" , value:"Successful exploitation of this
  vulnerability will allow remote attackers to cause denial of service, and web
  content could access information in the HTTP cache which can reveal some
  visited URLs and the contents of those pages.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"Mozilla Firefox version before 
  49.0.2 on MAC OS X.");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox version 49.0.2
  or later, For updates refer to http://www.mozilla.com/en-US/firefox/all.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-87/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ffVer = "";

## Get version
if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

# Check for vulnerable version
if(version_is_less(version:ffVer, test_version:"49.0.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"49.0.2");
  security_message(data:report);
  exit(0);
}
