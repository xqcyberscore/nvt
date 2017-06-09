###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_total_protection_mult_vuln.nasl 6155 2017-05-18 06:34:14Z cfi $
#
# McAfee Total Protection Multiple Vulnerabilities (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mcafee:total_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807237");
  script_version("$Revision: 6155 $");
  script_cve_id("CVE-2015-8772", "CVE-2015-8773");
  script_bugtraq_id(82143, 82144);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-18 08:34:14 +0200 (Thu, 18 May 2017) $");
  script_tag(name:"creation_date", value:"2016-02-08 17:22:31 +0530 (Mon, 08 Feb 2016)");
  script_name("McAfee Total Protection Multiple Vulnerabilities (Windows)");

  script_tag(name: "summary" , value:"This host is installed with McAfee Total
  Protection and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to:
  - The McAfee File Lock Driver does not handle correctly IOCTL_DISK_VERIFY
    IOCTL requests.
  - The McAfee File Lock Driver does not handle correctly GUIDs of the encrypted
    vaults.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to disclose sensitive information from kernel memory or crash the affected host.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"McAfee Total Protection kernel driver
  module 'McPvDrv.sys' version 4.6.111.0 and probably earlier.");

  script_tag(name: "solution" , value:"No solution or patch was made available for at least one year since disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one. ");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://www.nettitude.co.uk/mcafee-file-lock-driver-kernel-memory-leak");
  script_xref(name : "URL" , value : "https://www.nettitude.co.uk/mcafee-file-lock-driver-kernel-stack-based-bof");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_total_protection_detect.nasl");
  script_mandatory_keys("McAfee/TotalProtection/Win/Ver");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
syspath = "";
sysVer = "";

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Get file version
sysVer = fetch_file_version(sysPath, file_name:"system32\Drivers\McPvDrv.sys");
if(!sysVer){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less_equal(version:sysVer, test_version:"4.6.111.0"))
{
  report = report_fixed_ver(installed_version:sysVer, fixed_version: "None Available");
  security_message(data:report);
  exit(0);
}

