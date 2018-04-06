###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icq_remote_code_exec_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# ICQ 7 Instant Messaging Client Remote Code Execution Vulnerability
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

tag_impact = "Successful exploitation allows the man-in-the-middle attackers to
execute  arbitrary code via a crafted file that is fetched through an automatic
update mechanism.

Impact Level: System/Application";

tag_affected = "ICQ version 7.0 to 7.2(7.2.0.3525) on Windows";

tag_insight = "The flaw is due to an error in automatic update mechanism.
It does not check the identity of the update server or the authenticity
of the updates that it downloads through its automatic update mechanism.";

tag_solution = "Upgrade to ICQ 7.4.4629 or later,
For updates refer to http://www.icq.com";

tag_summary = "This host has ICQ installed and is prone remote code execution
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801574");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0487");
  script_bugtraq_id(45805);
  script_name("ICQ 7 Instant Messaging Client Remote Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/680540");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/515724");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_icq_detect.nasl");
  script_require_keys("ICQ/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

icqVer = get_kb_item("ICQ/Ver");
if(!icqVer){
  exit(0);
}

## Check for the version 7.2(7.2.0.3525)
if(version_in_range(version:icqVer, test_version:"7.0", test_version2:"7.2.0.3525")){
 security_message(0);
}
