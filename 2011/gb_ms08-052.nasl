###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-052.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft GDI Plus Remote Code Execution Vulnerabilities (954593)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to crash an affected application
  or execute arbitrary code.
  Impact Level: Application";
tag_affected = "Microsoft SQL Server 2005 SP 2/3
  Microsoft Office Excel Viewer 2007
  Microsoft Office XP/2003 SP 3 and prior
  Microsoft Office Visio 2002 SP 2 and prior
  Microsoft Office Groove 2007 SP1 and prior
  Microsoft Excel  Viewer 2003 SP 3 and prior
  Microsoft Office 2007 System SP 1/2 and prior
  Microsoft Office Word Viewer 2003 SP 3 and prior
  Microsoft Office Visio Viewer 2007 SP 2 and prior
  Microsoft Office PowerPoint Viewer 2007 SP 2 and prior
  Microsoft Visual Studio 2008 SP 1 and prior
  Microsoft Visual Studio .NET 2003 SP 1 and prior
  Microsoft Windows 2000 SP4 with Internet Explorer 6 SP 1
  Microsoft Office Compatibility Pack for Word/Excel/PowerPoint 2007 File Formats SP 1/2
  Microsoft Office PowerPoint Viewer 2003
  Microsoft Office PowerPoint Viewer 2007 Service Pack 1";
tag_insight = "The issues are caused by memory corruptions, integer, heap and buffer
  overflows, and input validation errors in GDI+ when rendering malformed WMF,
  PNG, TIFF and BMP images, or when processing Office Art Property Tables in
  Office documents.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-052.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-052.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801725");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-18 10:00:48 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-5348", "CVE-2008-3012", "CVE-2008-3013",
                "CVE-2008-3014", "CVE-2008-3015");
  script_bugtraq_id(31018, 31019, 31020, 31021, 31022);
  script_name("Microsoft Products GDI Plus Remote Code Execution Vulnerabilities (954593)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32154");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-052.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl",
                      "secpod_office_products_version_900032.nasl",
                      "secpod_reg_enum.nasl", "gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


function FileVer (file, path)
{
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:path);
  if(share =~ "[a-z]\$")
    share = toupper(share);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:path + file);
 ver = GetVer(file:file, share:share);
  return ver;
}


if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}


# Visio 2002
# Check for existence of Visio
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(item:"DisplayName", key:key + item);
  if("Visio" >< appName)
  {
    offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
    if(offPath)
    {
      offPath += "\Microsoft Shared\OFFICE10";
      dllVer = FileVer(file:"\Mso.dll", path:offPath);
      if(dllVer)
      {
        # Grep for Mso.dll version 10.0 < 10.0.6844.0
        if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.6843.9"))
        {
          security_message(0);
          exit(0);
        }
      }
    }
  }
}

# Office XP
if(get_kb_item("MS/Office/Ver") =~ "^10\..*")
{
  offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
  if(offPath)
  {
    offPath += "\Microsoft Shared\OFFICE10";
    dllVer = FileVer(file:"\Mso.dll", path:offPath);
    if(dllVer)
    {
      # Grep for Mso.dll version 10.0 < 10.0.6845.0
      if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.6844.9"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

# Office 2003 or Excel Viewer 2003 or Word Viewer 2003 or PowerPoint Viewer 2003
offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"ProgramFilesDir");
if(offPath)
{
  offPath = offPath + "\Microsoft Office\OFFICE11";

  dllVer = FileVer(file:"\Gdiplus.dll", path:offPath);
  if(dllVer)
  {
    # Grep for Gdiplus.dll version 11.0 < 11.0.8230.0
    if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8229.9"))
    {
      security_message(0);
      exit(0);
    }
  }
}


# Office 2007 or Groove 2007 or Excel Viewer or PowerPoint Viewer or
# Office Compatibility Pack 2007 or Visio Viewer 2007
if(((get_kb_item("MS/Office/Ver") =~ "^12\..*") ||
    (get_kb_item("SMB/Office/VisioViewer/Ver") =~ "^12\..*") ||
    (get_kb_item("SMB/Office/Groove/Version") =~ "^12\..*") ||
    (get_kb_item("SMB/Office/XLView/Version") =~ "^12\..*") ||
    (get_kb_item("SMB/Office/PPView/Version")) =~ "^12\..*")||
    (get_kb_item("SMB/Office/ComptPack/Version") =~ "^12\..*"))
{
  offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
  if(offPath)
  {
    offPath += "\Microsoft Shared\OFFICE12";
    dllVer = FileVer(file:"\Ogl.dll", path:offPath);
    if(dllVer)
    {
      # Grep for Ogl.dll version 12.0 < 12.0.6509.5000
      if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6509.4999"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

# Microsoft Visual Studio .Net 2003 and Microsoft Visual Studio .Net 2002
if(egrep(pattern:"^7\..*", string:get_kb_item("Microsoft/VisualStudio.Net/Ver")))
{
  vsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
  if(vsPath)
  {
    vsPath = vsPath + "\Microsoft Shared\Office10";
    vsVer = FileVer(file:"\MSO.DLL", path:vsPath);
    # Check for MSO.dll version 10.0 < 10.0.6844.0
    if(vsVer)
    {
      if(version_in_range(version:vsVer, test_version:"10.0", test_version2:"10.0.6843.9"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

# Visual Studio 2008
if(egrep(pattern:"^9\..*", string:get_kb_item("Microsoft/VisualStudio/Ver")))
{
  vsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Microsoft SDKs\Windows",
                           item:"CurrentInstallFolder");
  if(vsPath)
  {
    vsPath = vsPath + "\Bootstrapper\Packages\ReportViewer";
    rvVer = FileVer(file:"\ReportViewer.exe", path:vsPath);
    # Check for ReportViewer.exe 9.0 < 9.0.21022.143
    if(rvVer)
    {
      if(version_in_range(version:rvVer, test_version:"9.0", test_version2:"9.0.21022.142"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

# Windows 2K with IE 6 SP1
if(hotfix_check_sp(win2k:5) > 0)
{
  ieVer = get_kb_item("MS/IE/EXE/Ver");
  if(ieVer =~ "^6\.0\.2800")
  {
    dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"CommonFilesDir");
    if(dllPath)
    {
      dllPath += "\Microsoft Shared\VGX";
      dllVer = FileVer(file:"\vgx.dll", path:dllPath);
      if(dllVer)
      {
        # Grep for vgx.dll version < 6.0.2800.1612
        if(version_is_less(version:dllVer, test_version:"6.0.2800.1612"))
        {
          security_message(0);
          exit(0);
        }
      }
    }
  }
}

# Microsoft SQL Server 2005
key = "SOFTWARE\Microsoft\Microsoft SQL Server\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    sqlpath = registry_get_sz(key:key + item + "\Setup", item:"SQLBinRoot");
    sqlVer = FileVer (file:"\sqlservr.exe", path:sqlpath);
    # Check for SQL Server 2005 version 2005.90.3000 < 2005.90.3073.0
    if(sqlVer)
    {
      if(version_in_range(version:sqlVer, test_version:"2005.90.3000", test_version2:"2005.90.3072.9"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
