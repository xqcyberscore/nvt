###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_final_draft_file_parsing_mult_bof_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Final Draft Script File Parsing Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the system or cause the application to crash.
  Impact Level: System/Application";
tag_affected = "Final Draft version 8.0 before 8.02";
tag_insight = "The flaws are due to an errors when parsing certain tag elements like
  'Word', 'Transition', 'Location', 'Extension', 'SceneIntro', 'TimeOfDay',
  and 'Character' within a '.fdx' or '.fdxtscript' files, which can be
  exploited to cause a buffer overflow via files with overly long tag elements.";
tag_solution = "Upgrade to Final Draft Version 8.02 or later,
  For updates refer to http://www.finaldraft.com/index.php";
tag_summary = "This host is installed with Final Draft and is prone to multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802393");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-5059");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-07 18:05:02 +0530 (Tue, 07 Feb 2012)");
  script_name("Final Draft Script File Parsing Multiple Buffer Overflow Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47044");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18184/");
  script_xref(name : "URL" , value : "http://www.security-assessment.com/files/documents/advisory/Final_Draft-Multiple_Stack_Buffer_Overflows.pdf");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
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

## Variable Initialization
item = "";
fdraftname = "";
fdraftVer  = NULL;

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Application Registry Key
key = "SOFTWARE\Final Draft";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get registry key for uninstall
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ## Check for Displayname
  fdraftname = registry_get_sz(key:key + item, item:"DisplayName");
  if("Final Draft" >< fdraftname)
  {
    ## Get the version from registry
    fdraftVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    ## Check Final Draft version 8.0 prior 8.0.2
    if(!isnull(fdraftVer) && fdraftVer =~ "^8.*")
    {
      if(version_is_less(version:fdraftVer, test_version:"8.0.2"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
