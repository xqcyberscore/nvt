###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_security_advisory_3074162.nasl 6183 2017-05-22 09:03:43Z teissa $
#
# MS Malicious Software Removal Tool Privilege Escalation Security Advisory (3057154)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805937");
  script_version("$Revision: 6183 $");
  script_cve_id("CVE-2015-2418");
  script_bugtraq_id(75962);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-22 11:03:43 +0200 (Mon, 22 May 2017) $");
  script_tag(name:"creation_date", value:"2015-07-23 17:52:04 +0530 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS Malicious Software Removal Tool Privilege Escalation Security Advisory (3057154)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft advisory 3057154.");

  script_tag(name: "vuldetect" , value: "Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value: "The error exists as Microsoft Malicious
  Software Removal Tool (MSRT) fails to properly handle a race condition involving
  a DLL-planting scenario.");

  script_tag(name: "impact" , value: "Successful exploitation will allow attackers
  to gain elevated privileges on the affected machine.

  Impact Level: System");

  script_tag(name: "affected" , value:"Microsoft Malicious Software Removal Tool
  versions prior to 5.26.11603.0");

  script_tag(name: "solution" , value: "Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/3074162");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/3074162");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
exeVer = "";

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from 'Mrt.exe' file
exeVer = fetch_file_version(sysPath, file_name:"system32\Mrt.exe");
if(!exeVer){
  exit(0);
}

## Check if version < 5.26.11603.0
if(version_is_less(version:exeVer, test_version:"5.26.11603.0"))
{
  security_message(0);
  exit(0);
}
