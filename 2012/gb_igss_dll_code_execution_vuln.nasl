###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_igss_dll_code_execution_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Interactive Graphical SCADA System DLL Loading Arbitrary Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  code and conduct DLL hijacking attacks.
  Impact Level: System/Application";
tag_affected = "7T Interactive Graphical SCADA System (IGSS) versions prior to 9.0.0.11291";
tag_insight = "This flaw is due to the application insecurely loading certain
  libraries from the current working directory, which could allow attackers
  to execute arbitrary code by tricking a user into opening a file from a
  network share.";
tag_solution = "Apply the patch from below link,
  http://www.7t.dk/igss/igssupdates/v90/progupdatesv90.zip";
tag_summary = "This host is installed with Interactive Graphical SCADA System
  and is prone to code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802297");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-4053");
  script_bugtraq_id(51438);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-23 15:15:15 +0530 (Mon, 23 Jan 2012)");
  script_name("Interactive Graphical SCADA System DLL Loading Arbitrary Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51438");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-11-353-01.pdf");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
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

  ## Check for IGSS ODBC versions prior to 9.0.0.11291
  if(version_is_less(version:version, test_version:"9.0.0.11291")) {
    security_message(0);
  }
}
