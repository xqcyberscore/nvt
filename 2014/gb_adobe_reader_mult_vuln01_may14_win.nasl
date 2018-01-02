###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_vuln01_may14_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader Multiple Vulnerabilities - 01 May14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804606");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2014-0521", "CVE-2014-0522", "CVE-2014-0523", "CVE-2014-0524",
                "CVE-2014-0525", "CVE-2014-0526", "CVE-2014-0527", "CVE-2014-0528",
                "CVE-2014-0529");
  script_bugtraq_id(67363, 67360, 67368, 67369, 67365, 67370, 67367, 67366, 67362);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-05-22 10:46:12 +0530 (Thu, 22 May 2014)");
  script_name("Adobe Reader Multiple Vulnerabilities - 01 May14 (Windows)");

  tag_summary = "This host is installed with Adobe Reader and is prone to multiple
vulnerabilities.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "Multiple flaws exists,

- An error within the implementation of Javascript APIs.

- An error when validating user supplied paths.

- An integer overflow error when handling PDF417 barcodes.

- An error exists within the handling of certain API calls to unmapped memory.

- A use-after-free error when handling the messageHandler property of the
AcroPDF ActiveX control.

- A double-free error.

- Many other unspecified errors.";

  tag_impact = "Successful exploitation will allow attackers to conduct a denial of service,
disclose potentially sensitive information, bypass certain security
restrictions, execute arbitrary code and compromise a user's system.

Impact Level: System/Application";

  tag_affected = "Adobe Reader X before version 10.1.10 and XI before version 11.0.07 on
Windows.";

  tag_solution = "Upgrade to Adobe Reader X version 10.1.10 or XI version 11.0.07 or later.
For updates refer http://get.adobe.com/reader";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://securitytracker.com/id/1030229");
  script_xref(name : "URL" , value : "https://www.hkcert.org/my_url/en/alert/14051403");
  script_xref(name : "URL" , value : "http://helpx.adobe.com/security/products/reader/apsb14-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer && readerVer =~ "^(10|11)")
{
  ## Check Adobe Reader vulnerable versions
  if(version_in_range(version:readerVer, test_version:"10.0.0", test_version2:"10.1.09")||
     version_in_range(version:readerVer, test_version:"11.0.0", test_version2:"11.0.06"))
  {
    security_message(0);
    exit(0);
  }
}
