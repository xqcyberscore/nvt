###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-026.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# MS Forefront Unified Access Gateway Information Disclosure Vulnerability (2663860)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to obtain potentially sensitive
  information.
  Impact Level: Application";
tag_affected = "Microsoft Forefront Unified Access Gateway 2010 Service Pack 1
  Microsoft Forefront Unified Access Gateway 2010 Service Pack 1 Update 1";
tag_insight = "The flaws are due to an error,
  - In UAG allows redirecting users to an untrusted site.
  - Within the default website configuration allows access to certain content
    from the external network.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS12-026";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-026.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903018");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0146", "CVE-2012-0147");
  script_bugtraq_id(52909, 52903);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-12 16:00:48 +0530 (Thu, 12 Apr 2012)");
  script_name("MS Forefront Unified Access Gateway Information Disclosure Vulnerability (2663860)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48787");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74367");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74368");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74369");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026909");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS12-026");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_forefront_unified_access_gateway_detect.nasl");
  script_require_keys("MS/Forefront/UAG/Ver");
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

## Variable Initialization
dllVer = "";
uagVer = "";
path = "";

## Get the version from KB to confirm application is installed
uagVer = get_kb_item("MS/Forefront/UAG/Ver");
if(!uagVer){
  exit(0);
}

## Get Program Files Path
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"ProgramFilesDir");
if(!path){
  exit(0);
}

## Get the Whlfilter.dll file version
dllVer = fetch_file_version(sysPath:path,
         file_name:"Microsoft Forefront Unified Access Gateway\von\bin\Whlfilter.dll");

if(!dllVer){
  exit(0);
}

## Checking for Whlfilter.dll file version
if(version_in_range(version:dllVer, test_version:"4.0.1752.10000", test_version2:"4.0.1753.10075")||
   version_in_range(version:dllVer, test_version:"4.0.1773.10100", test_version2:"4.0.1773.10189")){
  security_message(0);
}
