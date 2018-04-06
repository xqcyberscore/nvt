###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_dotnet_security_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft .NET Framework Security Bypass Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow context-dependent attackers to bypass
  intended access restrictions.
  Impact Level: System/Application";
tag_affected = "Microsoft .NET Framework versions before 4 beta 2.";
tag_insight = "The flaw is due to an error in the JIT compiler, when
  'IsJITOptimizerDisabled' is set to false, fails to handle expressions
  related to null strings, which allows context-dependent attackers to bypass
  intended access restrictions in opportunistic circumstances by leveraging a
  crafted application.";
tag_solution = "Upgrade to Microsoft .NET Framework version 4 beta 2 or later.
  For updates refer to http://www.microsoft.com/net/download.aspx";
tag_summary = "The host is installed with Microsoft .NET Framework and is prone to
  security bypass vulnerability

  This NVT has been replaced by NVT secpod_ms11-044.nasl
  (OID:1.3.6.1.4.1.25623.1.0.902522).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902518");
  script_version("$Revision: 9351 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-1271");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Microsoft .NET Framework Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://stackoverflow.com/questions/2135509/bug-only-occurring-when-compile-optimization-enabled/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-044.nasl.

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm .NET
key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    path =  path + "\mscorlib.dll";
    share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:path);
    file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:path);

    ## Get version from mscorlib.dll file
    dllVer = GetVer(file:file, share:share);
    if(!dllVer) {
      exit(0);
    }
  }
}

## Check for Microsoft .NET Framework versions before 4 beta 2 (4.0.21006.1)
if(version_is_less(version:dllVer, test_version:"4.0.21006.1")){
  security_message(0);
}
