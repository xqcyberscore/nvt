###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panasonic_fpwin_pro_mult_vuln.nasl 5813 2017-03-31 09:01:08Z teissa $
#
# Panasonic FPWIN Pro Multiple Vulnerabilities 
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:panasonic:fpwin_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809029");
  script_version("$Revision: 5813 $");
  script_cve_id("CVE-2016-4496", "CVE-2016-4497", "CVE-2016-4498", "CVE-2016-4499");
  script_bugtraq_id(90520, 90523, 90521, 90522);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-31 11:01:08 +0200 (Fri, 31 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-09-01 13:08:12 +0530 (Thu, 01 Sep 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Panasonic FPWIN Pro Multiple Vulnerabilities");

  script_tag(name: "summary" , value:"The host is installed with 
  Panasonic FPWIN Pro and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The multiple flaws are due to,
  - A heap-based buffer overflow error.
  - An uninitialized pointer access error.
  - An out-of-bounds write error.
  - A type confusion error.");

  script_tag(name: "impact" , value:"Successful exploitation will allows local 
  users to cause a denial of service or possibly have unspecified other impact.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Panasonic FPWIN Pro 5.x through 7.x 
  before 7.130");

  script_tag(name: "solution" , value:"Upgrade to Panasonic FPWIN Pro version 
  7.130 or later, For updates refer to 
  https://www.panasonic-electric-works.com/eu/plc-software-control-fpwin-pro.htm");
 
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-16-332");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-16-334");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-16-335");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-16-330");
  script_xref(name : "URL" , value : "https://ics-cert.us-cert.gov/advisories/ICSA-16-131-01");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_panasonic_fpwin_pro_detect_win.nasl");
  script_mandatory_keys("Panasonic/FPWIN/Pro/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
fpwinVer = "";
report = "";

## Get version
if(!fpwinVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_in_range(version:fpwinVer, test_version:"5.0", test_version2:"7.122"))
{
  report = report_fixed_ver(installed_version:fpwinVer, fixed_version:"7.130");
  security_message(data:report);
  exit(0);
}
