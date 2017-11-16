##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bitdefender_ts_bdfwfpf_driver_local_priv_escalation_vuln.nasl 7771 2017-11-15 11:52:34Z jschulte $
#
# Bitdefender Total Security 'bdfwfpf' Kernel Driver Privilege Escalation Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:bitdefender:total_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811803");
  script_version("$Revision: 7771 $");
  script_cve_id("CVE-2017-10950");
  script_bugtraq_id(100418);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-15 12:52:34 +0100 (Wed, 15 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-09-05 16:45:12 +0530 (Tue, 05 Sep 2017)");
  script_name("Bitdefender Total Security 'bdfwfpf' Kernel Driver Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Bitdefender
  Total Security and is prone to local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error with the
  processing of the 0x8000E038 IOCTL in the bdfwfpf driver. The issue results
  from the lack of validating the existence of an object prior to performing
  operations on the object.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code in the context of SYSTEM with elevated
  privileges.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Bitdefender Total Security 21.0.24.62.");

  script_tag(name:"solution", value:"No solution or patch is available as of 15th
  November, 2017. Information regarding tis issue will be updated once the solution
  details are available. For updates refer to https://www.bitdefender.com");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://vuldb.com/de/?id.105907");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_bitdefender_prdts_detect.nasl");
  script_mandatory_keys("BitDefender/TotalSec/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
bitVer = "";

## Get version
if(!bitVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(bitVer == "21.0.24.62")
{
  report = report_fixed_ver(installed_version:bitVer, fixed_version:"NoneAvailable");
  security_message(data:report);
  exit(0);
}
