###############################################################################
# OpenVAS Vulnerability Test
# $Id: eliteCMS_multiple.nasl 4655 2016-12-01 15:18:13Z teissa $
#
# eliteCMS multiple Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "eliteCMS is prone to a vulnerability that lets attackers upload and
  execute arbitrary PHP code. The application is also prone to a
  cross-site scripting issue and to a SQL Injection Vulnerability.
  These issues occur because the application fails to sufficiently
  sanitize user-supplied input.

  Attackers can exploit these issues to steal cookie information,
  execute arbitrary client-side scripts in the context of the browser,
  upload and execute arbitrary files in the context of the webserver,
  compromise the application, access or modify data, exploit latent
  vulnerabilities in the underlying database and launch other attacks.

  These issues affect eliteCMS 1.01; other versions may also be
  affected.";


if (description)
{
 script_id(100222);
 script_version("$Revision: 4655 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-01 16:18:13 +0100 (Thu, 01 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-06-14 17:19:03 +0200 (Sun, 14 Jun 2009)");
 script_bugtraq_id(35155,30990);
 script_cve_id("CVE-2008-4046");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("eliteCMS multiple Vulnerabilities");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("eliteCMS_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50869");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35155");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/30990");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/eliteCMS")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

dir  = matches[2];

  if(!isnull(dir)) {
      url = string(dir, "/index.php?page=-1%27");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if( buf == NULL )exit(0);

      if(egrep(pattern:"You have an error in your SQL", string: buf))
        {    
   	   security_message(port:port);
           exit(0);
        } 
  }   

exit(0);
