###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_scriptftp_cmd_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# ScriptFTP 'GETLIST' or 'GETFILE' Commands Remote Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_affected = "ScriptFTP version 3.3 and prior.";

tag_insight = "The flaw is due to a boundary error when processing filenames
within a directory listing. This can be exploited to cause a stack-based buffer
overflow via a specially crafted FTP LIST command response.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with ScriptFTP and is prone to buffer
overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902571");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_bugtraq_id(49707);
  script_cve_id("CVE-2011-3976");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("ScriptFTP 'GETLIST' or 'GETFILE' Commands Remote Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46099/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17876/");
  script_xref(name : "URL" , value : "http://www.digital-echidna.org/2011/09/scriptftp-3-3-remote-buffer-overflow-exploit-0day/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Confirm ScriptFTP
key = "SOFTWARE\ScriptFTP";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Installed Path
path = registry_get_sz(key:key, item:"Install_Dir");
if(!path){
  exit(0);
}

## Get Version from ScriptFTP.exe
version = fetch_file_version(sysPath:path, file_name:"ScriptFTP.exe");
if(version)
{
  ## Check for ScriptFTP version 3.3 and prior.
  if(version_is_less_equal(version:version, test_version:"3.3")) {
    security_message(0);
  }
}
