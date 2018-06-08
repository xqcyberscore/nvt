###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_unspecified_vuln_feb18_win.nasl 10133 2018-06-08 11:13:34Z asteins $
#
# Google Chrome Unspecified Security Vulnerability Feb18 (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812805");
  script_version("$Revision: 10133 $");
  script_cve_id("CVE-2018-6056");
  script_bugtraq_id(103003);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 13:13:34 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-02-16 13:44:45 +0530 (Fri, 16 Feb 2018)");
  script_name("Google Chrome Unspecified Security Vulnerability Feb18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Google Chrome and is
  prone to an unspecified remote security vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an incorrect derived
  class instantiation in V8.");

  script_tag(name: "impact" , value:"Successful exploitation of this vulnerability
  will allow remote attacker to have unspecified impact on the affected system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Google Chrome version prior to 64.0.3282.167
  on Windows");

  script_tag(name: "solution" , value:"Upgrade to Google Chrome version 64.0.3282.167
  or later. For updates refer to http://www.google.com/chrome");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://chromereleases.googleblog.com/2018/02/stable-channel-update-for-desktop_13.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

vers = "";

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"64.0.3282.167"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"64.0.3282.167", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
