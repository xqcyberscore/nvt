###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_web_apps_ms13-084.nasl 6093 2017-05-10 09:03:18Z teissa $
#
# Microsoft Office Web Apps Remote Code Execution vulnerability (2885089)
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903327";
CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6093 $");
  script_cve_id("CVE-2013-3889", "CVE-2013-3895");
  script_bugtraq_id(62829, 62800);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-10-09 17:04:48 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Web Apps Remote Code Execution vulnerability (2885089)");

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
"Microsoft Web Applications 2010 Service Pack 2 and prior.
Microsoft Excel Web App 2010 Service Pack 1 and prior.";

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
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55131");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-084");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_mandatory_keys("MS/Office/Web/Apps/Ver");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
webappVer = "";
dllVer = "";
path = "";

if( ! infos = get_app_version_and_location( cpe:CPE ) ) exit( 0 );

## Get SharePoint Version
webappVer = infos['version'];
if(!webappVer){
  exit(0);
}

path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(webappVer =~ "^14\..*")
{
  ## Microsoft Office Web Apps 2010
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\wordserver\core\msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7108.4999"))
    {
      security_message(0);
      exit(0);
    }
  }

  ## Microsoft Office Excel Web App 2010
  dllVer2 = fetch_file_version(sysPath:path, file_name:"\14.0\Bin\Xlsrv.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.7108.4999"))
    {
      security_message(0);
      exit(0);
    }
  }
}
