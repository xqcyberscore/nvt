###############################################################################
# OpenVAS Vulnerability Test
# $Id: Beerwins_PhpLinkAdmin_1_0.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# Beerwin's PhpLinkAdmin Remote File Include and Multiple SQL
# Injection Vulnerabilities
#
# Authors:
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

tag_summary = "Beerwin's PhpLinkAdmin is prone to multiple input-validation
  vulnerabilities, including a remote file-include issue and multiple
  SQL-injection issues.

  A successful exploit may allow an attacker to execute malicious code
  within the context of the webserver process, compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  Beerwin's PhpLinkAdmin 1.0 is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_id(100058);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-03-18 10:43:43 +0100 (Wed, 18 Mar 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1024");
 script_bugtraq_id(34129);

 script_name("Beerwin's PhpLinkAdmin Remote File Include and Multiple SQL Injection Vulnerabilities");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34129");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


dir = make_list("/phplinkadmin",cgi_dirs());
foreach d (dir)
{ 
 url = string(d, "//edlink.php?linkid=-1%27%20union%20all%20select%201,2,3,4,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374%27--");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )continue;
 
 if( 
     egrep(pattern: "OpenVAS-SQL-Injection-Test", string: buf)
   )
   {    
    security_message(port:port);
    exit(0);
   }
}
exit(0);
