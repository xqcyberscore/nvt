###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_help_n_support_center_code_exec_vuln.nasl 8168 2017-12-19 07:30:15Z teissa $
#
# MS Windows Help and Support Center Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-06-16
# Updated CVSS score, Description, References and added the CVE-2010-2265
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-05-18
#  -This plugin is invalidated by secpod_ms10-042.nasl   
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


tag_solution = "Vendor has released a patch for the issue, refer below link for
patch. http://www.microsoft.com/technet/security/bulletin/ms10-042.mspx ";

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code or compromise a vulnerable system.

Impact Level: System";

tag_affected = "Windows XP Service Pack 2/3 Windows Server 2003 Service Pack 2.";

tag_insight = "The flaws are due to:
- An error in the 'MPC::HTML::UrlUnescapeW()' function within the Help and
Support Center application (helpctr.exe) that does not properly check the
return code of 'MPC::HexToNum()' when escaping URLs, which could allow
attackers to bypass whitelist restrictions and invoke arbitrary help files.
- An input validation error in the 'GetServerName()' function in the
'C:\WINDOWS\PCHealth\HelpCtr\System\sysinfo\commonFunc.js' script invoked via
'ShowServerName()' in 'C:\WINDOWS\PCHealth\HelpCtr\System\sysinfo\sysinfomain.htm',
which could be exploited by attackers to execute arbitrary scripting code.";

tag_summary = "This host is prone to remote code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801358");
  script_version("$Revision: 8168 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-1885", "CVE-2010-2265"); 
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("MS Windows Help and Support Center Remote Code Execution Vulnerability");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59267");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1417");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/2219475.mspx");
 
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

## This plugin is invalidated by secpod_ms10-042.nasl 
exit(66);

include("smb_nt.inc");
include("secpod_reg.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

if(registry_key_exists(key:"SOFTWARE\Classes\HCP")){
  security_message(0);
}
