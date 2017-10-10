###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_arbit_code_dos_vuln.nasl 7336 2017-10-04 05:42:02Z asteins $
#
# Foxit Reader Arbitrary Code Execution and Denial of Service Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112056");
  script_version("$Revision: 7336 $");
  script_cve_id("CVE-2017-14694");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-04 07:42:02 +0200 (Wed, 04 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-09-27 10:23:07 +0200 (Wed, 27 Sep 2017)");
  script_name("Foxit Reader Arbitrary Code Execution and Denial of Service Vulnerability (Windows)");

  script_tag(name: "summary", value:"The host is installed with Foxit Reader
  and is prone to a code execution and denial of service vulnerability");

  script_tag(name: "vuldetect", value:"Get the installed version with the help
  of the detection NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value:"Foxit Reader allows attackers to execute arbitrary code or
      cause a denial of service via a crafted .pdf file, related to 'Data from Faulting Address controls Code Flow starting at
      tiptsf!CPenInputPanel::FinalRelease+0x000000000000002f'.");

  script_tag(name: "impact", value:"Successful exploitation will allow local
  attackers to crash the application via a buffer overflow.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Foxit Reader version 8.3.2.25013 on Windows");
  script_tag(name: "solution" , value:"No solution is available as of 27th September, 2017.
  Information regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.foxitsoftware.com");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name: "URL" , value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-14694");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect.nasl");
  script_mandatory_keys("Foxit/Reader/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:ver, test_version:"8.3.2.25013"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"None");
  security_message(data:report);
  exit(0);
}
