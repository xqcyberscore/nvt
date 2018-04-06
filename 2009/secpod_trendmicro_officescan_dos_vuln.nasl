###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trendmicro_officescan_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Trend Micro OfficeScan Client Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the

tag_impact = "Successful exploitation will let the attacker terminate 'NTRtScan.exe' process
  and temporarily disable the real time scanning protection for the system by
  crafting a directory.
  Impact Level: System/Application";
tag_affected = "Trend Micro OfficeScan 8.0 Service Pack 1";
tag_insight = "This flaw is due to an error while scanning directories as it fails to
  handle nested directories with excessively long names.";
tag_solution = "Upgrade to Trend Micro OfficeScan 10 or later,
  For updates refer to http://www.trendmicro.com/download/engine.asp";
tag_summary = "This host is installed with Trend Micro OfficeScan Client and is prone to
  Denial of Service Vulnerability.";
 # GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900634");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1435");
  script_bugtraq_id(34642);
  script_name("Trend Micro OfficeScan Client Denial Of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34737");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1146");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/502847/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
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
include("secpod_smb_func.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\TrendMicro\NSC\PFW";
if(!registry_key_exists(key:key)){
  exit(0);
}

scanPath = registry_get_sz(key:key, item:"InstallPath");
if(!scanPath){
  exit(0);
}

scanPath += "PccNTMon.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:scanPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:scanPath);

fileVer = GetVer(file:file, share:share);
if(fileVer != NULL)
{
  # OfficeScan 8.0 build 3110 and prior (SP1 Patch 1/8.0.0.3110)
  if(version_is_less_equal(version:fileVer, test_version:"8.0.0.3110")){
    security_message(0);
  }
}
