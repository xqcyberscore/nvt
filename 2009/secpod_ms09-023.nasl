###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-023.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Windows Search Script Execution Vulnerability (963093)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2012-03-22
#  Updated Application confirmation.
#  Used fetch_file_version() to get the version.
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Remote attackers could exploit this issue to obtain sensitive information
  or access to data on the affected system by convincing a user to download
  a crafted file to a specific location, and then open an application that
  loads the file.
  Impact Level: System";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.";
tag_insight = "The flaw is caused because the search function does not properly restrict the
  environment within which scripts execute, which could allow sensitive
  information disclosure.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-023.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-023.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900568");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-10 20:01:05 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0239");
  script_bugtraq_id(35220);
  script_name("Microsoft Windows Search Script Execution Vulnerability (963093)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35366");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/963093");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-023.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

# Check for Hotfix 963093 (MS09-023).
if(hotfix_missing(name:"963093") == 0){
  exit(0);
}

# Windows Search 4.0 is required
searchName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\Uninstall\KB940157", item:"DisplayName");

## Confirm Windows Search 4.0 is installed
if("Windows Search 4.0" ><  searchName && searchName)
{
  ## Get System Path
  sysPath = smb_get_systemroot();
  if(!sysPath){
    exit(0);
  }

  ## Get Version from Spupdsvc.exe file
  exeVer = fetch_file_version(sysPath, file_name:"system32\Spupdsvc.exe");
  if(exeVer)
  {
    # Check for Spupdsvc.exe < 6.3.15.0
    if(version_is_less(version:exeVer, test_version:"6.3.15.0")){
      security_message(0);
    }
  }
}
