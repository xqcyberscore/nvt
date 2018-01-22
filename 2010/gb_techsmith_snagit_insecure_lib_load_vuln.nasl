###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_techsmith_snagit_insecure_lib_load_vuln.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# TechSmith Snagit Insecure Library Loading Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary code and conduct DLL hijacking attacks.

Impact Level: Application";

tag_affected = "TechSmith Snagit Version 10 (Build 788)";

tag_insight = "This flaw is due to the application insecurely loading certain
librairies from the current working directory, which could allow attackers
to execute arbitrary code by tricking a user into opening a file from a
network share.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with TechSmith Snagit and is prone to
insecure library loading vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801274");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_cve_id("CVE-2010-3130");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("TechSmith Snagit Insecure Library Loading Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41124");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14764/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm TechSmith Snagit
if(!registry_key_exists(key:"SOFTWARE\TechSmith\SnagIt\")){
    exit(0);
}

## Get Application Installed Path
snagPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\SnagIt32.exe", item:"Path");
if(!snagPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:snagPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:snagPath +
                            "\SnagIt32.exe");

## Get TechSmith Snagit Version
snagVer = GetVer(share:share, file:file);

if(snagVer != NULL)
{
  ##Check for TechSmith Snagit Version 10 (Build 788)
  if(version_is_equal(version:snagVer, test_version: "10.0.0.788")){
    security_message(0);
  }
}
