###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mpg123_player_dos_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# mpg123 Player Denial of Service Vulnerability (Linux).
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

tag_impact = "Successful exploitation will let the attacker trigger out of bounds
  memory access and thus execute arbitrary code and possibly crash the
  application.

  Impact level: Application";

tag_affected = "mpg123 Player prior to 1.7.2 on Linux.";
tag_insight = "This flaw is due to integer signedness error in the store_id3_text function
  in the ID3v2 code when processing ID3v2 tags with negative encoding values.";
tag_solution = "Update to version 1.7.2
  http://www.mpg123.de/download.shtml";
tag_summary = "This host is running mpg123 Player which is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900538");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1301");
  script_bugtraq_id(34381);
  script_name("mpg123 Player Denial of Service Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34587");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0936");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_mpg123_detect_lin.nasl");
  script_require_keys("mpg123/Linux/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

mpgVer = get_kb_item("mpg123/Linux/Ver");
if(mpgVer == NULL){
  exit(0);
}

if(version_is_less(version:mpgVer, test_version:"1.7.2")){
  security_message(0);
}
