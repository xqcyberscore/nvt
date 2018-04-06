###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ccproxy_connection_req_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# CCProxy CONNECTION Request Buffer Overflow Vulnerability.
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

tag_impact = "Attackers can exploit this issue to cause a stack based buffer overflow and
  to execute arbitrary code in the scope of affected application.";
tag_affected = "Youngzsoft CCProxy 6.61 and prior on Windows.";
tag_insight = "Boundary error in the CCProxy while processing of CONNECT requests sent to
  the HTTP proxy having overly long hostname.";
tag_solution = "Upgrade to CCProxy version 6.62 or later,
  http://www.youngzsoft.net/ccproxy/proxy-server-download.htm";
tag_summary = "This host is running CCProxy and is prone to buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800539");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-16 10:38:04 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6415");
  script_bugtraq_id(31416);
  script_name("CCProxy CONNECTION Request Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/31997");
  script_xref(name : "URL" , value : "http://jbrownsec.blogspot.com/2008/09/ccproxy-near-stealth-patching.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ccproxy_detect.nasl", "find_service.nasl");
  script_require_keys("CCProxy/Ver");
  script_require_ports("Services/www", 808);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

ccproxyPort = 808;
if(!get_port_state(ccproxyPort)){
  exit(0);
}

ccproxyVer = get_kb_item("CCProxy/Ver");
if(ccproxyVer)
{
  if(version_is_less(version:ccproxyVer, test_version:"6.62")){
    security_message(ccproxyPort);
  }
}
