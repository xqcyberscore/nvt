###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4022169.nasl 10180 2018-06-13 14:35:18Z santu $
#
# Microsoft Outlook 2013 Service Pack 1 Elevation of Privilege Vulnerability (KB4022169)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813432");
  script_version("$Revision: 10180 $");
  script_cve_id("CVE-2018-8244");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-06-13 16:35:18 +0200 (Wed, 13 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-13 10:35:48 +0530 (Wed, 13 Jun 2018)");
  script_name("Microsoft Outlook 2013 Service Pack 1 Elevation of Privilege Vulnerability (KB4022169)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4022169");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Outlook
  does not validate attachment headers properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to send an email with hidden attachments that would be opened or
  executed once a victim clicks a link within the email.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Outlook 2013 Service Pack 1");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4022169");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");

if(!outlookVer || !(outlookVer =~ "^15\.")){
  exit(0);
}

outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
if(!outlookFile){
  exit(0);
}

outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
if(!outlookVer){
  exit(0);
}

if(version_in_range(version:outlookVer, test_version:"15.0", test_version2:"15.0.5041.0999"))
{
  report = report_fixed_ver(file_checked: outlookFile + "outlook.exe",
                            file_version:outlookVer, vulnerable_range:"15.0 - 15.0.5041.0999");
  security_message(data:report);
  exit(0);
}
exit(99);
