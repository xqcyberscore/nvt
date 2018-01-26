###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_weborf_44506.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# Weborf HTTP Request Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Weborf is prone to a denial-of-service vulnerability.

Remote attackers can exploit this issue to cause the application to
crash, denying service to legitimate users.

Versions prior to Weborf 0.12.4 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100878");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-29 12:58:08 +0200 (Fri, 29 Oct 2010)");
 script_bugtraq_id(44506);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Weborf HTTP Request Denial Of Service Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44506");
 script_xref(name : "URL" , value : "http://galileo.dmi.unict.it/wiki/weborf/doku.php");
 script_xref(name : "URL" , value : "http://galileo.dmi.unict.it/wiki/weborf/doku.php?id=news:released_0.12.4");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_MIXED_ATTACK);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_weborf_webserver_detect.nasl", "gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Weborf/banner");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:8080);

banner = get_http_banner(port:port);
if("Server: Weborf" >!< banner)exit(0);

if(safe_checks()) {

  if(!vers = get_kb_item(string("www/", port, "/Weborf")))exit(0);
  if(!isnull(vers) && vers >!< "unknown") {

    if(version_is_less(version: vers, test_version: "0.12.4")) {
      security_message(port:port);
      exit(0);
    }  
  
  }  

} else {  

  req = string("GET\t/\tHTTP/1.0\r\n\r\n");
  res = http_send_recv(port:port, data:req);

  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }  
}

exit(0);



