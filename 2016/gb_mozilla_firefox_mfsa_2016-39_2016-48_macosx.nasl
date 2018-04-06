###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2016-39_2016-48_macosx.nasl 9341 2018-04-06 05:27:04Z cfischer $
#
# Mozilla Firefox Security Updates( mfsa_2016-39_2016-48 )-MAC OS X
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
  script_oid("1.3.6.1.4.1.25623.1.0.807679");
  script_version("$Revision: 9341 $");
  script_cve_id("CVE-2016-2820", "CVE-2016-2808", "CVE-2016-2817", "CVE-2016-2816", 
		"CVE-2016-2814", "CVE-2016-2811", "CVE-2016-2812", "CVE-2016-2807", 
                "CVE-2016-2806", "CVE-2016-2804");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 07:27:04 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-05-02 12:27:09 +0530 (Mon, 02 May 2016)");
  script_name("Mozilla Firefox Security Updates( mfsa_2016-39_2016-48 )-MAC OS X");

  script_tag(name: "summary" , value:"This host is installed with 
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The multiple flaws exists. For details
  refer the reference links.");

  script_tag(name: "impact" , value:"Successful exploitation of this
  vulnerability will allow remote attackers to conduct Universal XSS
  (UXSS) attacks, to execute arbitrary code, to bypass the Content
  Security Policy (CSP) protection mechanism, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"Mozilla Firefox version before 
  46 on MAC OS X.");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox version 46
  or later, For updates refer to http://www.mozilla.com/en-US/firefox/all.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-48/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-47/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-46/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-45/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-44/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-43/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-42/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-41/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-40/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-39/");

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
if(version_is_less(version:ffVer, test_version:"46"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"46");
  security_message(data:report);
  exit(0);
}
