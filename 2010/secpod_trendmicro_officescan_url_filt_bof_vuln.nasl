###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trendmicro_officescan_url_filt_bof_vuln.nasl 8266 2018-01-01 07:28:32Z teissa $
#
# Trend Micro OfficeScan URL Filtering Engine Buffer Overflow Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
################################################################################

tag_impact = "Successful exploitation lets the attackers to cause a denial of service
  or execute arbitrary code via HTTP request that lacks a method token or
  format string specifiers in PROPFIND request.
  Impact Level: Application/System";
tag_affected = "Trend Micro OfficeScan 8.0 before SP1 Patch 5 - Build 3510
  Trend Micro OfficeScan 10.0 before Build 1224";
tag_insight = "The flaw is due to an unspecified error in the Trend Micro URL
  filtering (TMUFE) engine while processing malformed data which can be
  exploited to cause a buffer overflow and crash or hang the application.";
tag_solution = "Apply Critical Patch Build 1224 for Trend Micro OfficeScan v10.0, and
  Patch 5 Build 3510 for Trend Micro OfficeScan v8.0 Service Pack 1,
  For updates refer to http://www.trendmicro.com/Download/product.asp?productid=5";
tag_summary = "This host has Trend Micro OfficeScan running which is prone to
  Buffer Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900231");
  script_version("$Revision: 8266 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 08:28:32 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(38083);
  script_cve_id("CVE-2010-0564");
  script_name("Trend Micro OfficeScan URL Filtering Engine Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38396");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56097");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0295");
  script_xref(name : "URL" , value : "http://www.trendmicro.com/ftp/documentation/readme/readme_1224.txt");
  script_xref(name : "URL" , value : "http://www.trendmicro.com/ftp/documentation/readme/OSCE_80_Win_SP1_Patch_5_en_readme.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get Trend Micro OfficeScan Version
trendMicroOffKey = "SOFTWARE\TrendMicro\OfficeScan\service\Information";
trendMicroOffVer = registry_get_sz(key:trendMicroOffKey,
                                   item:"Server_Version");

## Check Trend Micro OfficeScan Version 8 or 10
if(trendMicroOffVer =~ "^(8|10)")
{
  ## Set Minimum Required Version
  if(trendMicroOffVer =~ "^8"){
    minRequireVer = "3.0.0.1029";
  }else{
    minRequireVer = "2.0.0.1049";
  }

  ## Get Trend Micro OfficeScan Installed Path
  trendMicroOffPath = registry_get_sz(key:trendMicroOffKey, item:"Local_Path");
  if(!trendMicroOffPath){
    exit(0);
  }

  ## Get Dll Version
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$",
                       string:trendMicroOffPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:trendMicroOffPath + "Pccnt\Common\tmufeng.dll");
  dllVer = GetVer(file:file, share:share);

  ## Check version < 3.0.0.1029 for Trend Micro OfficeScan 8
  ## Check version < 2.0.0.1049 for Trend Micro OfficeScan 10
  if(version_is_less(version:dllVer, test_version:minRequireVer)){
    security_message(0);
  }
}
