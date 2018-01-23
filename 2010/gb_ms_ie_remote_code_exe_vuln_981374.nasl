###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_remote_code_exe_vuln_981374.nasl 8495 2018-01-23 07:57:49Z teissa $
#
# MS Internet Explorer Remote Code Execution Vulnerability (981374)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_solution = "Apply the updates. For more information refer,
http://technet.microsoft.com/en-us/security/bulletin/MS10-018";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 6.x, 7.x";
tag_insight = "The flaw exists due to an invalid pointer reference being made within
  Internet Explorer. In specially-crafted attack, attempting to access a freed
  object, it can be caused to execute arbitrary code.";
tag_summary = "The host is installed with Internet Explorer and is prone to Remote
  Code Execution Vulnerability.

  This NVT has been replaced by NVT secpod_ms10-018.nasl
  (OID:1.3.6.1.4.1.25623.1.0.902155).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800176");
  script_version("$Revision: 8495 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0806");
  script_bugtraq_id(38615);
  script_name("MS Internet Explorer Remote Code Execution Vulnerability (981374)");

  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Mar/1023699.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/981374.mspx");
  script_xref(name : "URL" , value : "http://www.trustedsource.org/blog/388/Targeted-Internet-Explorer-0day-Attack-Announced-CVE-2010-0806");
  script_xref(name : "URL" , value : "http://www.freevirusremovalguide.com/18401/targeted-internet-explorer-0day-attack-announced-cve-2010-0806/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms10-018.nasl.

include("smb_nt.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(ieVer =~ "^(6|7)*"){
  security_message(0);
}
