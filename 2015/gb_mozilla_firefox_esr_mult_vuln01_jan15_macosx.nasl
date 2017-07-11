###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mult_vuln01_jan15_macosx.nasl 6229 2017-05-29 09:04:10Z teissa $
#
# Mozilla Firefox ESR Multiple Vulnerabilities-01 Jan15 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805251");
  script_version("$Revision: 6229 $");
  script_cve_id("CVE-2014-8641", "CVE-2014-8639", "CVE-2014-8638", "CVE-2014-8634");
  script_bugtraq_id(72044, 72046, 72047, 72049);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-29 11:04:10 +0200 (Mon, 29 May 2017) $");
  script_tag(name:"creation_date", value:"2015-01-20 13:36:16 +0530 (Tue, 20 Jan 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 Jan15 (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Mozilla Firefox ESR
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exist due to,
  - A use-after-free error when handling tracks within WebRTC.
  - An error when handling a '407 Proxy Authentication' response with a
  'Set-Cookie' header from a web proxy.
  - Some unspecified errors.
  - An error when handling a request from 'navigator.sendBeacon' API interface
  function.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions, and compromise a user's
  system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Mozilla Firefox ESR 31.x before 31.4 on
  Mac OS X");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox ESR version 31.4
  or later, For updates refer to https://www.mozilla.org/en-US/firefox/organizations");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62253");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-06");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-04");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-03");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-01");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
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
if(ffVer =~ "^(31)\.")
{
  if((version_in_range(version:ffVer, test_version:"31.0", test_version2:"31.3")))
  {
    fix = "31.4";
    report = 'Installed version: ' + ffVer + '\n' +
             'Fixed version:     ' + fix  + '\n';
    security_message(data:report );
    exit(0);
  }
}
