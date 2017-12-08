# OpenVAS Vulnerability Test
# $Id: oracle_xsql_query.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Oracle XSQL Sample Application Vulnerability
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to www.kb.cert.org
#
# Copyright:
# Copyright (C) 2001 Matt Moore
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "One of the sample applications that comes with 
the Oracle XSQL Servlet allows an attacker to make arbitrary queries to 
the Oracle database (under an unprivileged account). 
Whilst not allowing an attacker to delete or modify database contents, 
this flaw can be used to enumerate database users and view table names.";

tag_solution = "Sample applications should always be removed from
production servers.

Reference : http://www.kb.cert.org/vuls/id/717827";


if(description)
{
 script_id(10613);
 script_version("$Revision: 8023 $");
 script_cve_id("CVE-2002-1630", "CVE-2002-1631", "CVE-2002-1632");
 script_bugtraq_id(6556);
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "Oracle XSQL Sample Application Vulnerability";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2001 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Checqueryk starts here
# Check uses a default sample page supplied with the XSQL servlet. 

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 req = http_get(item:"/xsql/demo/adhocsql/query.xsql?sql=select%20username%20from%20ALL_USERS", port:port);
 r   = http_keepalive_send_recv(port:port, data:req);
 if(r =~ "HTTP/1\.[0|1] 200" && "USERNAME" >< r)	
 	security_message(port);
}
