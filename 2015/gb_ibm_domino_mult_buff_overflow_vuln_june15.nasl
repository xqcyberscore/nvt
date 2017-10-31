###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_mult_buff_overflow_vuln_june15.nasl 7575 2017-10-26 09:47:04Z cfischer $
#
# IBM Domino Multiple Stack-based Buffer Overflow Vulnerabilities - June15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805644");
  script_version("$Revision: 7575 $");
  script_cve_id("CVE-2015-1903", "CVE-2015-1902");
  script_bugtraq_id(74598, 74597);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:47:04 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-06-04 12:22:20 +0530 (Thu, 04 Jun 2015)");
  script_name("IBM Domino Multiple Stack-based Buffer Overflow Vulnerabilities - June15");

  script_tag(name:"summary", value:"This host is installed with IBM Domino and
  is prone to multiple stack-based buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - An overflow condition in nrouter.exe which is triggered as user-supplied
    input is not properly validated when handling the BMP color palette.
  - An integer overflow condition in the nrouter.exe component that is triggered
    as BMP image dimensions in emails are not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause a stack-based buffer overflow, resulting in a denial of service or
  potentially allowing the execution of arbitrary code.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"IBM Domino 8.5 before 8.5.3 FP6 IF7 and 9.0
  before 9.0.1 FP3 IF3.");

  script_tag(name:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF7 or
  9.0.1 FP3 IF3 or later. For more information refer to,
  http://www-01.ibm.com/support/docview.wss?uid=swg21700029");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21883245");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");
  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

## Variable Initialization
domVer = "";

if(!domVer = get_highest_app_version(cpe:CPE)){
  exit(0);
}

domVer1 = ereg_replace(pattern:"FP", string:domVer, replace: ".");

if(version_in_range(version:domVer1, test_version:"8.5", test_version2:"8.5.3.6"))
{
  fix = "8.5.3 FP6 IF7";
  VULN = TRUE;
}

if(version_in_range(version:domVer1, test_version:"9.0", test_version2:"9.0.1.3"))
{
  fix = "9.0.1 FP3 IF3";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed Version: ' + domVer + '\nFixed Version: ' + fix + '\n';
  security_message(data:report, port:0);
  exit(0);
}
