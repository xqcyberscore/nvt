###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_security_bypass_vuln_feb16_macosx.nasl 5850 2017-04-04 09:01:03Z teissa $
#
# Mozilla Firefox Security Bypass Vulnerability - Feb16 (Mac OS X)
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807069");
  script_version("$Revision: 5850 $");
  script_cve_id("CVE-2016-1949");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-04 11:01:03 +0200 (Tue, 04 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-02-15 12:47:02 +0530 (Mon, 15 Feb 2016)");
  script_name("Mozilla Firefox Security Bypass Vulnerability - Feb16 (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Mozilla
  Firefox and is prone to same-origin policy bypass vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to improper restriction of 
  the interaction between Service Workers and plugins.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  remote attackers to bypass the Same Origin Policy via a crafted web site that 
  triggers spoofed responses to requests that use NPAPI.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Mozilla Firefox version before 44.0.2 on
  Mac OS X.");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox version 44.0.2
  or later, For updates refer to http://www.mozilla.com/en-US/firefox/all.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-13");

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
if(version_is_less(version:ffVer, test_version:"44.0.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"44.0.2");
  security_message(data:report);
  exit(0);
}
