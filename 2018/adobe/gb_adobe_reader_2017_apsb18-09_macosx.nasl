###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_2017_apsb18-09_macosx.nasl 10480 2018-07-11 10:23:47Z santu $
#
# Adobe Reader 2017 Security Updates(apsb18-09)-MAC OS X
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813233");
  script_version("$Revision: 10480 $");
  script_cve_id("CVE-2018-4990", "CVE-2018-4947", "CVE-2018-4948", "CVE-2018-4966",
                "CVE-2018-4968", "CVE-2018-4978", "CVE-2018-4982", "CVE-2018-4984",
                "CVE-2018-4996", "CVE-2018-4952", "CVE-2018-4954", "CVE-2018-4958",
                "CVE-2018-4959", "CVE-2018-4961", "CVE-2018-4971", "CVE-2018-4974",
                "CVE-2018-4977", "CVE-2018-4980", "CVE-2018-4983", "CVE-2018-4988",
                "CVE-2018-4989", "CVE-2018-4950", "CVE-2018-4979", "CVE-2018-4949",
                "CVE-2018-4951", "CVE-2018-4955", "CVE-2018-4956", "CVE-2018-4957",
                "CVE-2018-4962", "CVE-2018-4963", "CVE-2018-4964", "CVE-2018-4967",
                "CVE-2018-4969", "CVE-2018-4970", "CVE-2018-4972", "CVE-2018-4973",
                "CVE-2018-4975", "CVE-2018-4976", "CVE-2018-4981", "CVE-2018-4986",
                "CVE-2018-4985", "CVE-2018-4953", "CVE-2018-4987", "CVE-2018-4965",
                "CVE-2018-4993", "CVE-2018-4995", "CVE-2018-4960");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-11 12:23:47 +0200 (Wed, 11 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-05-15 12:13:36 +0530 (Tue, 15 May 2018)");
  script_name("Adobe Reader 2017 Security Updates(apsb18-09)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader 2017
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to double
  Free, heap overflow, use-after-free, out-of-bounds write, security bypass,
  out-of-bounds read, type confusion, untrusted pointer dereference, memory
  corruption, NTLM SSO hash theft and HTTP POST new line injection via XFA
  submission errors.");

  script_tag(name:"impact" , value:"Successful exploitation will allow an
  attacker to bypass security, disclose information and run arbitrary code in the
  context of the current user.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Adobe Acrobat Reader 2017 prior to version
  2017.011.30080 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat Reader 2017 version
  2017.011.30080 or later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name: "URL" , value :"https://helpx.adobe.com/security/products/acrobat/apsb18-09.html");
  script_xref(name: "URL" , value :"http://www.adobe.com/in/products/acrobat.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
readerVer = infos['version'];
InstallPath = infos['location'];

if(version_in_range(version:readerVer, test_version:"17.0", test_version2:"17.011.30079"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"2017.011.30080", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
exit(0);
