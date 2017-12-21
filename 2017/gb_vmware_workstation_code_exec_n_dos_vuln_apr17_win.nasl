###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_workstation_code_exec_n_dos_vuln_apr17_win.nasl 8200 2017-12-20 13:48:45Z cfischer $
#
# VMware Workstation Code Execution And DoS Vulnerabilities Apr17 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:vmware:workstation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810744");
  script_version("$Revision: 8200 $");
  script_cve_id("CVE-2015-2340", "CVE-2015-2339", "CVE-2015-2338", "CVE-2015-2337",
                "CVE-2015-2336", "CVE-2012-0897");
  script_bugtraq_id(75092, 75095, 51426);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 14:48:45 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-04-07 17:06:57 +0530 (Fri, 07 Apr 2017)");
  script_name("VMware Workstation Code Execution And DoS Vulnerabilities Apr17 (Windows)");

  script_tag(name: "summary" , value:"The host is installed with VMware Workstation
  Player and is prone to code execution and denial-of-service vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to errror in the
  'TPView.dll' and 'TPInt.dll' which incorrectly handles memory allocation.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to execute arbitrary code and conduct a denial-of-service condition.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"VMware Workstation Player 10.x before
  10.0.6 and 11.x before 11.1.1 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Workstation Player version
  10.0.6 or 11.1.1 or later, For updates refer to http://www.vmware.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_mandatory_keys("VMware/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
vmwareVer = "";

## Get version
if(!vmwareVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(vmwareVer =~ "^10\.")
{
  if(version_is_less(version:vmwareVer, test_version:"10.0.6"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"10.0.6");
    security_message(data:report );
    exit(0);
  }
}

else if(vmwareVer =~ "^11\.")
{
  if(version_is_less(version:vmwareVer, test_version:"11.1.1"))
  {
    report = report_fixed_ver(installed_version:vmwareVer, fixed_version:"11.1.1");
    security_message(data:report );
    exit(0);
  }
}
