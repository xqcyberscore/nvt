###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sharepoint_foundation_ms13-084.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# Microsoft SharePoint Foundation Remote Code Execution vulnerability (2885089)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903326";
CPE = "cpe:/a:microsoft:sharepoint_foundation";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6065 $");
  script_cve_id("CVE-2013-3889", "CVE-2013-3895");
  script_bugtraq_id(62829, 62800);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name:"creation_date", value:"2013-10-09 16:29:38 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft SharePoint Foundation Remote Code Execution vulnerability (2885089)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS13-084.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is due to improper sanitation of user supplied input via a specially
crafted Excel file.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code,
cause a DoS (Denial of Service), and compromise a vulnerable system.

Impact Level: System/Application";

  tag_affected =
"Microsoft SharePoint Foundation 2010 Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms13-084";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55131");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-084");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Foundation/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
shareVer = "";
dllVer = "";
path = "";

## Get SharePoint Version
shareVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!shareVer){
  exit(0);
}

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## SharePoint Foundation 2010
if(shareVer =~ "^14\..*")
{
  path = registry_get_sz(key: key + "14.0", item:"Location");

  dllVer = fetch_file_version(sysPath:path, file_name:"BIN\Onetutil.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7106.5001"))
    {
      security_message(0);
      exit(0);
    }
  }
}
