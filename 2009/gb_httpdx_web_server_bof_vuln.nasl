###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdx_web_server_bof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# httpdx Web Server 'h_handlepeer()' Buffer Overflow Vulnerability
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

tag_impact = "Remote attackers can exploit this issue to execute arbitrary code or crash
  the server via a specially crafted request.
  Impact Level: Application";
tag_affected = "httpdx Web Server version 1.4.3 and prior on windows.";
tag_insight = "A boundary error occurs in 'h_handlepeer()' in 'http.cpp' while processing
  overly long HTTP requests leading to buffer overflow.";
tag_solution = "Upgrade to httpdx Server version 1.4.4 or later
  http://sourceforge.net/projects/httpdx/";
tag_summary = "The host is running httpdx Web Server and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800962");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3711");
  script_name("httpdx Web Server 'h_handlepeer()' Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36991");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2874");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507042/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_httpdx_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

httpdxPort = get_http_port(default:80);
if(!httpdxPort){
  exit(0);
}

httpdxVer = get_kb_item("httpdx/" + httpdxPort + "/Ver");
if(!isnull(httpdxVer))
{
  # Check for versions prior to 1.4.4
  if(version_is_less(version:httpdxVer, test_version:"1.4.4")){
    security_message(httpdxPort);
  }
}
