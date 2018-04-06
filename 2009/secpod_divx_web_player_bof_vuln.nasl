###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_divx_web_player_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# DivX Web Player Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application by tricking a user into
  opening a crafted DivX file.

  Impact level: System";

tag_affected = "DivX Web Player 1.4.2.7 and prior on Windows.";
tag_insight = "This flaw is due to the boundary checking error while processing Stream
  Format 'STRF' chunks which causes heap overflow.";
tag_solution = "Update to version 1.4.3.4
  http://www.divx.com/downloads/divx";
tag_summary = "This host is running DivX Web Player which is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900537");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5259");
  script_bugtraq_id(34523);
  script_name("DivX Web Player Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/377996.php");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33196");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1044");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_divx_web_player_detect.nasl");
  script_require_keys("DivX/Web/Player/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("version_func.inc");

divxVer = get_kb_item("DivX/Web/Player/Ver");
if(divxVer == NULL){
  exit(0);
}

if(version_is_less(version:divxVer, test_version:"1.4.3.4")){
  security_message(0);
}
