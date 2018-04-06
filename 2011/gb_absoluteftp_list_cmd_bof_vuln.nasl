###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_absoluteftp_list_cmd_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# AbsoluteFTP 'LIST' Command Remote Buffer Overflow Vulnerability
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

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary code within the context of the application. Failed attacks may cause
a denial of service condition.

Impact Level: System/Application";

tag_affected = "AbsoluteFTP versions 1.9.6 through 2.2.10";

tag_insight = "The flaw is due to a boundary error when processing an overly
long 'LIST' command. This can be exploited to cause a stack-based buffer
overflow via a specially crafted FTP LIST command.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with AbsoluteFTP and is prone to buffer
overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802271");
  script_version("$Revision: 9351 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"creation_date", value:"2011-11-10 16:16:16 +0530 (Thu, 10 Nov 2011)");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_name("AbsoluteFTP 'LIST' Command Remote Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71210");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18102");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/106797/absoluteftp-overflow.txt");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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

## Confirm AbsoluteFTP
key = "SOFTWARE\VanDyke\AbsoluteFTP\Install";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Installed Path
path = registry_get_sz(key:key, item:"Main Directory");
if(!path){
  exit(0);
}

## Get Version from AbsoluteFTP.exe
version = fetch_file_version(sysPath:path, file_name:"AbsoluteFTP.exe");
if(version)
{
  ## Check for AbsoluteFTP versions
  if(version_in_range(version:version, test_version:"1.9.6", test_version2:"2.2.10.252")){
    security_message(0);
  }
}
