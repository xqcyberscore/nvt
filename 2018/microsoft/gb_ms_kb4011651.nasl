###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4011651.nasl 8539 2018-01-25 14:37:09Z gveerendra $
#
# Microsoft Office Word Multiple Vulnerabilities (KB4011651)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812711");
  script_version("$Revision: 8539 $");
  script_cve_id("CVE-2018-0793", "CVE-2018-0794", "CVE-2018-0797", "CVE-2018-0798",
                "CVE-2018-0804", "CVE-2018-0805", "CVE-2018-0806", "CVE-2018-0807",
                "CVE-2018-0845", "CVE-2018-0848", "CVE-2018-0849", "CVE-2018-0862");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 15:37:09 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-10 12:33:34 +0530 (Wed, 10 Jan 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Multiple Vulnerabilities (KB4011651)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4011651.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The way that Microsoft Outlook parses specially crafted email messages.

  - Microsoft Office software fails to properly handle objects in memory.

  - Microsoft Office software fails to properly handle RTF files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user, perform other 
  actions in the security context of the current user and also to take control 
  of an affected system. An attacker could then install programs; view, change, 
  or delete data; or create new accounts with full user rights.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Word 2013 Service Pack 1");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link,
  https://support.microsoft.com/en-us/help/4011651");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4011651");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}


include("version_func.inc");

exeVer = "";
exePath = "";

exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer =~ "^(15\.)" && version_is_less(version:exeVer, test_version:"15.0.4997.1000"))
{
  report = report_fixed_ver(file_checked:exePath + "winword.exe",
           file_version:exeVer, vulnerable_range:"15 - 15.0.4997.0999");
  security_message(data:report);
  exit(0);
}
exit(0);
