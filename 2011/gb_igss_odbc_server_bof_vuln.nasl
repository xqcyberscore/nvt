###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_igss_odbc_server_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Interactive Graphical SCADA System ODBC Server Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with with administrative privileges. Failed exploit attempts will
  result in a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "7T Interactive Graphical SCADA System (IGSS) versions prior to 9.0.0.11143";
tag_insight = "The flaw is caused by a memory corruption error in the Open Database
  Connectivity (ODBC) component when processing packets sent to TCP port 20222.";
tag_solution = "Apply the patch from below link,
  http://www.7t.dk/igss/igssupdates/v90/progupdatesv90.zip";
tag_summary = "This host is installed with Interactive Graphical SCADA System
  and is prone to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802241");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2011-2959");
  script_bugtraq_id(47960);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Interactive Graphical SCADA System ODBC Server Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44345/");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/May/168");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/518110");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_igss_detect.nasl");
  script_require_keys("IGSS/Win/Ver");
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

## Get version from KB
version = get_kb_item("IGSS/Win/Ver");
if(! version){
  exit(0);
}

## Check for IGSS versions prior to 9.0
if(version_is_less(version:version, test_version:"9.0"))
{
  security_message(0);
  exit(0);
}

## Check for IGSS Patch
if(version =~ "^9\.0\.*")
{
  ## Get ODBC Server Path
  key = "SOFTWARE\7-Technologies\IGSS32\v9.00.00\ENVIRONMENT";
  if(!registry_key_exists(key:key)){
    exit(0);
  }

  odbcPath = registry_get_sz(key:key, item:"IGSSWORK");
  if(! odbcPath){
    exit(0);
  }

  ## Get Version from Odbcixv9se.exe
  odbcVer = fetch_file_version(sysPath:odbcPath, file_name:"Odbcixv9se.exe");
  if(! odbcVer){
   exit(0);
  }

  ## Check for IGSS ODBC versions prior to 9.0.0.11143
  if(version_is_less(version:version, test_version:"9.0.0.11143")) {
    security_message(0);
  }
}
