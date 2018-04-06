###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bopup_server_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Bopup Communication Server Remote Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary code with
  SYSTEM privileges or can crash an affected server.
  Impact Level: Application/System.";
tag_affected = "Bopup Communications Server version 3.2.26.5460 and prior";
tag_insight = "The flaw is due to a boundary error that can be exploited to cause
  a stack-based buffer overflow via a specially crafted TCP packet sent to
  port 19810.";
tag_solution = "Upgrade to Bopup Communications Server version 3.3.14.8456 or later
  For updates refer to http://www.blabsoft.com/products/server";
tag_summary = "This host has Bopup Communication Server installed and is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900687");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2227");
  script_name("Bopup Communication Server Remote Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9002");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/product/25643/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1645");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_bopup_server_detect.nasl");
  script_require_keys("Bopup/Server/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

bopupPort = 19810;
if(!get_port_state(bopupPort)){
  exit(0);
}

bopupVer = get_kb_item("Bopup/Server/Ver");
if(bopupVer != NULL)
{
  if(version_is_less_equal(version:bopupVer, test_version:"3.2.26.5460")){
    security_message(bopupPort);
  }
}
