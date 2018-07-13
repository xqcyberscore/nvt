###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4018338.nasl 10484 2018-07-11 14:03:19Z santu $
#
# Microsoft Access Remote Code Execution Vulnerability (KB4018338)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813657");
  script_version("$Revision: 10484 $");
  script_cve_id("CVE-2018-8312");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-07-11 16:03:19 +0200 (Wed, 11 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-11 11:24:45 +0530 (Wed, 11 Jul 2018)");
  script_name("Microsoft Access Remote Code Execution Vulnerability (KB4018338)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4018338.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Access software 
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to take control of the affected system. An attacker could then install programs,
  view, change, or delete data or create new accounts with full user rights. 

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Access 2016.");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4018338");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Access/Version");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

accVer = get_kb_item("SMB/Office/Access/Version");
if(!accVer){
  exit(0);
}

if(version_in_range(version:accVer, test_version:"16.0", test_version2:"16.0.4711.999"))
{
  report = report_fixed_ver(file_checked:"msaccess.exe",
           file_version:accVer, vulnerable_range:"16.0 - 16.0.4711.999");
  security_message(data:report);
  exit(0);
}
exit(0);
