###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sharepoint_services_ms14-022.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# Microsoft SharePoint Services 3.0 Multiple Vulnerabilities (2952166)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804583";
CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2014-0251");
  script_bugtraq_id(67283);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-14 14:57:22 +0530 (Wed, 14 May 2014)");
  script_name("Microsoft SharePoint Services 3.0 Multiple Vulnerabilities (2952166)");

  tag_summary =
"This host is missing an critical security update according to Microsoft
Bulletin MS14-022.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaws is due to multiple unspecified components when handling page content.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute the arbitrary
code and compromise a vulnerable system.

Impact Level: System/Application ";

  tag_affected =
"Microsoft SharePoint Services 3.0 32/64 bit Service Pack 3 and prior.";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms14-022";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57834");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms14-022");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
shareVer = "";
dllVer2 = "";
dllVer = "";
exeVer = "";
path = "";

## Get SharePoint Version
shareVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!shareVer){
  exit(0);
}

## SharePoint Server 2007
if(shareVer =~ "^12\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\12\BIN";

    dllVer = fetch_file_version(sysPath:path, file_name:"Onetutil.dll");

    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6690.4999"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
