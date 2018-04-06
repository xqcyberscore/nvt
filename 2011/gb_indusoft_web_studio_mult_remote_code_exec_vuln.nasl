###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_indusoft_web_studio_mult_remote_code_exec_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# InduSoft Web Studio Multiple Remote Code Execution Vulnerabilitites
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  within the context of the affected application.
  Impact Level: Application.";
tag_affected = "InduSoft Web Studio version 6.1 and 7.0";

tag_solution = "Install the hotfix from below link
  http://www.indusoft.com/hotfixes/hotfixes.php

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_insight = "The flaws are due to
  - An error in 'CEServer component'. When handling the remove File operation
    (0x15) the process blindly copies user supplied data to a fixed-length
    buffer on the stack.
  - An error in remote agent component (CEServer.exe). When handling incoming
    requests the process fails to perform any type of authentication, which
    allows direct manipulation and creation of files on disk, loading of
    arbitrary DLLs and process control.";
tag_summary = "This host is installed with Indusoft Web Studio and is prone to
  multiple remote code execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802537");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4051", "CVE-2011-4052");
  script_bugtraq_id(50675, 50677);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-07 17:02:41 +0530 (Wed, 07 Dec 2011)");
  script_name("InduSoft Web Studio Multiple Remote Code Execution Vulnerabilitites");

  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-329/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-330/");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-11-319-01.pdf");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm windows platform
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm InduSoft Web Studio installed
if(!registry_key_exists(key:"SOFTWARE\InduSoft Ltd.")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Check for InduSoft Web Studio DisplayName
  indName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Confirm the Software
  if("InduSoft Web Studio" >< indName)
  {
    ## Get the version from Registry
    indVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!indVer){
      exit(0);
    }

    ## match the version
    indVer = eregmatch(pattern:"v?([0-9.]+)", string:indVer);
    if(indVer[1])
    {
      ## Check for version
      if(version_is_equal(version:indVer[1], test_version:"6.1") ||
         version_is_equal(version:indVer[1], test_version:"7.0"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
