###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_groove_server_ms13-035.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Groove Server HTML Sanitisation Component XSS Vulnerability (2821818)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow an attacker to bypass certain security
  restrictions and conduct cross-site scripting and spoofing attacks.
  Impact Level: Application";

tag_affected = "Microsoft Groove Server 2010 Service Pack 1";
tag_insight = "Certain unspecified input is not properly sanitized within the HTML
  Sanitation component before being returned to the user. This can be
  exploited to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-035";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-035.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902962");
  script_version("$Revision: 9353 $");
  script_bugtraq_id(58883);
  script_cve_id("CVE-2013-1289");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-10 10:59:55 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft Groove Server HTML Sanitisation Component XSS Vulnerability (2821818)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52928/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687424");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-035");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
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

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Variables Initialization
dllVer = "";
dllPath = "";
dllVer = "";

## Microsoft Groove 2010
key = "SOFTWARE\Microsoft\Office Server\14.0\Groove\Groove Relay";
if(!registry_key_exists(key:key)){
  exit(0);
}

dllPath =  registry_get_sz(key:key, item:"RelayCFg");
if(dllPath)
{
  dllPath = dllPath - "RelayCfg.cpl";
  dllVer = fetch_file_version(sysPath:dllPath, file_name:"Groovers.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6126.4999"))
    {
      security_message(0);
      exit(0);
    }
  }
}
