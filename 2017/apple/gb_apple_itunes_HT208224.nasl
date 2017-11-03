###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_HT208224.nasl 7628 2017-11-02 12:00:39Z santu $
#
# Apple iTunes Security Updates( HT208224 )
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811957");
  script_version("$Revision: 7628 $");
  script_cve_id("CVE-2017-13784", "CVE-2017-13785", "CVE-2017-13783", "CVE-2017-13788", 
		"CVE-2017-13795", "CVE-2017-13802", "CVE-2017-13792", "CVE-2017-13791", 
		"CVE-2017-13798", "CVE-2017-13796", "CVE-2017-13793", "CVE-2017-13794", 
		"CVE-2017-13803" );
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-02 13:00:39 +0100 (Thu, 02 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-02 17:19:55 +0530 (Thu, 02 Nov 2017)");
  script_name("Apple iTunes Security Updates( HT208224 )");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to multiple
  memory corruption issues.");

  script_tag(name: "impact" , value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to perform arbitrary code execution.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple iTunes versions before 12.7.1");

  script_tag(name: "solution" , value:"Upgrade to Apple iTunes 12.7.1 or later.
  For updates refer to http://www.apple.com/support.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://support.apple.com/en-us/HT208224");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

ituneVer= "";

if(!ituneVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:ituneVer, test_version:"12.7.1"))
{
  report = report_fixed_ver(installed_version:ituneVer, fixed_version:"12.7.1");
  security_message(data:report);
  exit(0);
}
exit(0);
