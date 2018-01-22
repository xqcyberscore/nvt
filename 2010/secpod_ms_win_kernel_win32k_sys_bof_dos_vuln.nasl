###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_win_kernel_win32k_sys_bof_dos_vuln.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Microsoft Windows win32k.sys Driver 'CreateDIBPalette()' BOF Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to crash an affected
system or potentially execute arbitrary code with kernel privileges.

Impact Level: System";

tag_affected = "Microsoft Windows 7
Microsoft Windows XP SP3 and prior.
Microsoft Windows Vista SP 2 and prior.
Microsoft Windows Server 2008 SP 2 and prior.
Microsoft Windows Server 2003 SP 2 and prior.";

tag_insight = "The flaw is due to a buffer overflow error in the
'CreateDIBPalette()' function within the kernel-mode device driver 'Win32k.sys',
when using the 'biClrUsed' member value of a 'BITMAPINFOHEADER' structure as a
counter while retrieving Bitmap data from the clipboard.";

tag_solution = "Apply the latest updates from the below link.
http://www.microsoft.com/en/us/default.aspx";

tag_summary = "This host is prone to buffer ovreflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902256");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-2739");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows win32k.sys Driver 'CreateDIBPalette()' BOF Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40870");
  script_xref(name : "URL" , value : "http://www.ragestorm.net/blogs/?p=255");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2029");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
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
include("secpod_smb_func.inc");

exit(0); ##plugin may results to FP

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

## check the existence of the file for win2k, winxp, win2003
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");

if(sysPath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Win32k.sys");

  sysVer = GetVer(file:file, share:share);
  if(!isnull(sysVer))
  {
    security_message(0);
    exit(0);
  }
}

## check the existence of the file for , winVista, win2008, win7
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                         item:"PathName");
if(sysPath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:sysPath + "\system32\Win32k.sys");
  sysVer = GetVer(file:file, share:share);
  if(!isnull(sysVer)){
    security_message(0);
  }
}
