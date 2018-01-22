###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_vbscript_remote_code_exec_vuln.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# MS Internet Explorer 'VBScript' Remote Code Execution Vulnerability (981169)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Apply the latest updates. For more information refer,
  http://technet.microsoft.com/en-us/security/advisory/981169";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  via specially crafted attack.
  Impact Level: System";
tag_affected = "Microsoft Internet Explorer version 6.x, 7.x, 8.x";
tag_insight = "The flaw exists in the way that 'VBScript' interacts with Windows Help files
  when using Internet Explorer. If a malicious Web site displayed a specially
  crafted dialog box and a user pressed the F1 key, it allows arbitrary code
  to be executed in the security context of the currently logged-on user.";
tag_summary = "The host is installed with Internet Explorer and VBScript and is
  prone to Remote Code Execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800482");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0483");
  script_bugtraq_id(38463);
  script_name("MS Internet Explorer 'VBScript' Remote Code Execution Vulnerability");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

exit(0); ## Plugin may results to FP

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(ieVer =~ "^[6|7|8]\.*")
{
  exePath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(!exePath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                      string:exePath + "\winhlp32.exe");
  dllVer = GetVer(file:file, share:share);
  if(!isnull(dllVer)){
    security_message(0);
  }
}
