###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elecard_mpeg_player_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Elecard MPEG Player Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary
  codes in the context of the application and may cause stack overflow in
  the application.";
tag_affected = "Elecard MPEG Player 5.5 build 15884.081218 and prior.";
tag_insight = "Issue is with boundary error while processing playlist 'm3u' files, which
  may contain crafted long URLs.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://www.elecard.com/products/products-pc/consumer/mpeg-player";
tag_summary = "This host is running Elecard MPEG Player and is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800511");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0491");
  script_bugtraq_id(33089);
  script_name("Elecard MPEG Player Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33355");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7637");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_elecard_mpeg_player_detect.nasl");
  script_require_keys("Elecard/Player/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

epVer = get_kb_item("Elecard/Player/Ver");
if(epVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:epVer, test_version:"5.5.15884.081218")){
  security_message(0);
}
