###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_convert_to_pdf_mult_vuln_win.nasl 5910 2017-04-10 08:31:29Z teissa $
#
# Foxit Reader 'ConvertToPDF' TIFF Parsing Multiple Vulnerabilities (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107143");
  script_version("$Revision: 5910 $");
  script_cve_id("CVE-2017-6883");
  script_bugtraq_id(96870);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-10 10:31:29 +0200 (Mon, 10 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-04-05 18:47:49 +0530 (Wed, 05 Apr 2017)");
  script_name("Foxit Reader 'ConvertToPDF' TIFF Parsing Multiple Vulnerabilities (Windows)");

  script_tag(name: "summary" , value:"The host is installed with Foxit Reader
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists within the parsing of TIFF
  images. The issue results from the lack of proper validation of user-supplied
  data which can result in a read past the end of an allocated object."); 

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to cause a denial of service (out-of-bounds read and application crash) 
  via a crafted TIFF image. The vulnerability could lead to information disclosure; 
  an attacker can leverage this in conjunction with other vulnerabilities to execute 
  code in the context of the current process.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Foxit Reader version prior to 8.2.1 on
  windows");

  script_tag(name: "solution" , value:"Upgrade to Foxit Reader version 8.2.1 or
  later, For updates refer to http://www.foxitsoftware.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value:"http://www.zerodayinitiative.com/advisories/ZDI-17-133");
  script_xref(name : "URL" , value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect.nasl");
  script_mandatory_keys("Foxit/Reader/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
foxitVer = "";

## Get version
if(!foxitVer = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

## Check for vulnerable version
if(version_is_less_equal(version:foxitVer, test_version:"8.2.0.2051"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.2.1");
  security_message(data:report);
  exit(0);
}
