###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bsplayer_bls_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# BSPlayer Stack Overflow Vulnerability BLS
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker craft a malicious arbitrary
  'bls' file and cause stack overflow in the context of the affected
  application or can also cause remote code execution.

  Impact level: Application";

tag_affected = "BSPlayer Version prior to 2.36.990 on Windows.";
tag_insight = "This flaw is due to boundary check error while the user supplies input data
  in the context of the application.";
tag_solution = "Upgrade to the latest version 2.36.990
  http://www.bsplayer.org/en/bs.player/download";
tag_summary = "This host is running BSPlayer Free Edition and is prone to Stack
  Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800269");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1068");
  script_bugtraq_id(34190);
  script_name("BSPlayer Stack Overflow Vulnerability BLS");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34412");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8249");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8251");
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/9sg_bsplayer_seh.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_bsplayer_detect.nasl");
  script_require_keys("BSPlayer/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("version_func.inc");

playerVer = get_kb_item("BSPlayer/Ver");
if(playerVer != NULL)
{
  # Grep for BSPlayer Free Edition version prior to 2.36.990
  if(version_is_less(version:playerVer, test_version:"2.36.990")){
    security_message(0);
  }
}
