###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mbedthis_webapp_http_trace_method_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mbedthis AppWeb HTTP TRACE Method Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to gain sensitive information
  or inject arbitrary web script or HTML. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks.
  Impact Level: System/Application";
tag_affected = "Mbedthis AppWeb versions prior to 2.2.2";
tag_insight = "The flaw is due to improper handling of HTTP requests using the
  'TRACE' method,  which allows attackers to inject arbitrary HTML via
  crafted HTTP TRACE request.";
tag_solution = "Disable TRACE method or upgrade to Mbedthis AppWeb 2.2.2 or later
  For updates refer to http://appwebserver.org/index.html";
tag_summary = "The host is running Mbedthis AppWeb Server and is prone to cross
  site scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802350");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2007-3008");
  script_bugtraq_id(24456);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-02 14:47:36 +0530 (Fri, 02 Dec 2011)");
  script_name("Mbedthis AppWeb HTTP TRACE Method Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/25636");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/867593");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/34854");
  script_xref(name : "URL" , value : "http://www.appwebserver.org/forum/viewtopic.php?t=996");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_require_ports("Services/www", 7777);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Check for the default port
if(!port = get_http_port(default:7777)){
  port = 7777;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get the path
req = http_get(item:"/doc/product/index.html", port:port);
res = http_send_recv(port:port, data:req);

## Confirm the application before trying exploit
if("<title>Mbedthis AppWeb" >< res || "<title>Mbedthis Appweb" >< res)
{
  ## Construct the attack (TRACE) request
  req = string("TRACE /doc/product/index.html HTTP/1.1\r\n",
               "Host: ", get_host_name(), "\r\n\r\n");
  res = http_send_recv(port:port, data:req);

  ## Confirm the exploit (supports TRACE method or not)
  if(egrep(pattern:"^HTTP/.* 200 OK", string:res) && "TRACE" >< res &&
                   "UnknownMethod 400 Bad Request" >!< res){
    security_message(port);
  }
}
