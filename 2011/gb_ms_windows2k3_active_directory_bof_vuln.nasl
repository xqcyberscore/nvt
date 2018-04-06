###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows2k3_active_directory_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows2k3 Active Directory 'BROWSER ELECTION' Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation allows attackers to execute arbitrary code
with SYSTEM-level privileges or cause a denial of service condition.

Impact Level: System";

tag_affected = "Microsoft Windows 2K3 Service Pack 2 and prior";

tag_insight = "The flaw is due to an error in Active Directory in 'Mrxsmb.sys',
which fails to perform adequate boundary-checks on user-supplied data in crafted
BROWSER ELECTION request.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Active Directory and is prone to buffer
overflow vulnerability.

This NVT has been replaced by NVT secpod_ms11-019.nasl
(OID:1.3.6.1.4.1.25623.1.0.900279).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801598");
  script_version("$Revision: 9351 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-18 17:42:11 +0100 (Fri, 18 Feb 2011)");
  script_cve_id("CVE-2011-0654");
  script_bugtraq_id(46360);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows2k3 Active Directory 'BROWSER ELECTION' Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16166");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/current/0284.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
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

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-019.nasl.

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Check for the existence of file
dllVer = fetch_file_version(sysPath, file_name:"system32\drivers\mrxsmb.sys");
if(dllVer){
  security_message(0);
}
