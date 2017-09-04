##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_stable-channel-update-for-desktop-2017-08_macosx.nasl 7022 2017-08-30 08:57:06Z santu $
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-08)-Mac OS X
#
# Authors:
# Kashinath T <tkashinath@secpod.com> 
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811641");
  script_version("$Revision: 7022 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-08-30 10:57:06 +0200 (Wed, 30 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-29 11:54:39 +0530 (Tue, 29 Aug 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-08)-Mac OS X");

  script_tag(name: "summary" , value:"The host is installed with Google Chrome
  and is prone to an unknown vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an unknown error.");

  script_tag(name: "impact" , value:"Successful exploitation of these
  vulnerabilities will allow remote attacker to bypass security, execute
  arbitrary code, cause denial of service and conduct spoofing attacks.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Google Chrome version prior to 60.0.3112.113 on Mac OS X");

  script_tag(name: "solution", value:"Upgrade to Google Chrome version 60.0.3112.113 or later.
  For updates refer to http://www.google.com/chrome");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://chromereleases.googleblog.com/2017/08/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
chr_ver = "";

## Get version
if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:chr_ver, test_version:"60.0.3112.113"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"60.0.3112.113");
  security_message(data:report);
  exit(0);
}
