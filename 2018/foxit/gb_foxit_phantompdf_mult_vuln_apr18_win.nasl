###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantompdf_mult_vuln_apr18_win.nasl 9628 2018-04-26 12:03:30Z santu $
#
# Foxit PhantomPDF Multiple Vulnerabilities-Apr18 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813157");
  script_version("$Revision: 9628 $");
  script_cve_id("CVE-2018-3842", "CVE-2017-17557", "CVE-2017-14458", "CVE-2018-3853",
                "CVE-2018-3850", "CVE-2018-3843", "CVE-2018-10302");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 14:03:30 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-25 14:50:06 +0530 (Wed, 25 Apr 2018)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities-Apr18 (Windows)");

  script_tag(name: "summary" , value:"The host is installed with Foxit PhantomPDF
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,

  - An error where the application passes an insufficiently qualified path in
    loading an external library when a user launches the application.

  - A heap buffer overflow error.

  - Multiple use-after-free errors.

  - The use of uninitialized new 'Uint32Array' object or member variables in
    'PrintParams' or 'm_pCurContex' objects.

  - An incorrect memory allocation, memory commit, memory access, or array access.

  - Type Confusion errors.

  - An error in 'GoToE' & 'GoToR' Actions.

  - An out-of-bounds read error in the '_JP2_Codestream_Read_SOT' function.

  - An error since the application did not handle a COM object properly.

  - An error allowing users to embed executable files.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition, execute arbitrary code and
  gain access to sensitive data from memory.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Foxit PhantomPDF versions 9.0.1.1049 and
  prior on windows");

  script_tag(name: "solution" , value:"Upgrade to Foxit Reader version 9.1 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value:"http://www.foxitsoftware.com");
  script_xref(name : "URL" , value:"https://www.foxitsoftware.com/support/security-bulletins.php#content-2018");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("Foxit/PhantomPDF/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
pdfVer = infos['version'];
pdfPath = infos['location'];

## 9.1 == 9.1.0.5096
if(version_is_less(version:pdfVer, test_version:"9.1.0.5096"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.1", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(0);
