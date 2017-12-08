# OpenVAS Vulnerability Test
# $Id: iis_anything_idq.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: IIS IDA/IDQ Path Disclosure
#
# Authors:
# Filipe Custodio <filipecustodio@yahoo.com>
# Changes by rd :
# - description slightly modified to include a solution
#
# Copyright:
# Copyright (C) 2000 Filipe Custodio
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

tag_summary = "IIS 4.0 allows a remote attacker to obtain the real pathname
of the document root by requesting non-existent files with
.ida or .idq extensions.

An attacker may use this flaw to gain more information about
the remote host, and hence make more focused attacks.";

tag_solution = "Select 'Preferences ->Home directory ->Application',
and check the checkbox 'Check if file exists' for the ISAPI
mappings of your server.";

if(description)
{
 script_id(10492);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1065);
 script_cve_id("CVE-2000-0071");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "IIS IDA/IDQ Path Disclosure";
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");

 script_copyright("This script is Copyright (C) 2000 Filipe Custodio");
 family = "Web Servers";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("IIS/banner");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


sig = get_http_banner(port:port);
if ( "IIS" >!< sig ) exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 req = http_get(item:"/anything.idq", port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
 str = tolower(str);
  
 if ( egrep(pattern:"[a-z]\:\\.*anything",string:str) ) {
   security_message( port:port );
 } else {
   req = http_get(item:"/anything.ida", port:port);
   soc = http_open_socket(port);
   if(!soc)exit(0);
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
   str = tolower(str);
   if ( egrep(pattern:"[a-z]\:\\.*anything", string:str) )
      security_message( port:port );
   }
}
