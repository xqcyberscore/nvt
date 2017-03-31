###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_video_actvx_bof_vuln_jul09.nasl 5363 2017-02-20 13:07:22Z cfi $
#
# Microsoft Video ActiveX Control 'msvidctl.dll' BOF Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
#  Updated to MS09-032 Bulletin (973346) #3502
#    - By Sharath S <sharaths@secpod.com> on 2009-07-15
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-30
#      - To confirm the vulnerability on vista and win 2008
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

tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS09-032.mspx

  Workaround:
  Set the killbit for the CLSID {0955AC62-BF2E-4CBA-A2B9-A63F772D46CF}
  http://www.microsoft.com/technet/security/advisory/972890.mspx";

tag_impact = "Successful exploitation could allow execution of arbitrary code that affects
  the TV Tuner library, and can cause memory corruption.
  Impact Level: Application";
tag_affected = "Microsoft Video ActiveX Control on Windows 2000/XP/2003";
tag_insight = "- Stack-based buffer overflow error in MPEG2TuneRequest in msvidctl.dll in
    Microsoft DirectShow can be exploited via a crafted web page.
  - Unspecified error in msvidctl.dll is caused via unknown vectors that trigger
    memory corruption.";
tag_summary = "This host is installed with Microsoft Video ActiveX Control and is prone to
  Buffer Overflow vulnerability.";

if(description)
{
  script_id(800829);
  script_version("$Revision: 5363 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 14:07:22 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0015", "CVE-2008-0020");
  script_bugtraq_id(35558);
  script_name("Microsoft Video ActiveX Control 'msvidctl.dll' BOF Vulnerability");

  script_xref(name : "URL" , value : "http://www.iss.net/threats/329.html");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35683");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/972890");
  script_xref(name : "URL" , value : "http://isc.sans.org/diary.html?storyid=6733");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

## This function will return the version of the given file
function get_file_version(sysPath, file_name)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:sysPath + "\" + file_name);

  sysVer = GetVer(file:file, share:share);
  if(!sysVer){
    return(FALSE);
  }

  return(sysVer);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# MS09-032 Hotfix (973346)
if(hotfix_missing(name:"973346") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  vers = get_file_version(sysPath, file_name:"msvidctl.dll");
  if(!vers){
    exit(0);
  }
}

if(egrep(pattern:"^6\..*", string:vers))
{
  # Check if Kill-Bit is set for ActiveX control
  if(is_killbit_set(clsid:"{0955AC62-BF2E-4CBA-A2B9-A63F772D46CF}") == 0){
    security_message(0);
  }
}

## Get System Path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}
dllVer = get_file_version(sysPath, file_name:"System32\msvidctl.dll");
if(!dllVer){
  exit(0);
}

if(egrep(pattern:"^6\..*", string:dllVer))
{ 
  # Check if Kill-Bit is set for ActiveX control
  if(is_killbit_set(clsid:"{0955AC62-BF2E-4CBA-A2B9-A63F772D46CF}") == 0){
    security_message(0);
  }
}
