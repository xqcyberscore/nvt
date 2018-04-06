# OpenVAS Vulnerability Test
# $Id: snitz_forums_2000_sql_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Snitz Forums 2000 SQL injection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Netwok Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host is using Snitz Forum 2000

This version allow an attacker to execute stored procedures 
and non-interactive operating system commands on the system. 

The problem stems from the fact that the 'Email' variable
in the register.asp module fails to properly validate and
strip out malicious SQL data.  

An attacker, exploiting this flaw, would need network access
to the webserver.  A successful attack would allow the 
remote attacker the ability to potentially execute arbitrary
system commands through common SQL stored procedures such 
as xp_cmdshell.";

tag_solution = "Upgrade to version 3.4.03 or higher";

if (description)
{
script_oid("1.3.6.1.4.1.25623.1.0.14227");
script_version("$Revision: 9348 $");
script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
script_bugtraq_id(7549);
 script_cve_id("CVE-2003-0286");
 script_xref(name:"OSVDB", value:"4638");

 script_name("Snitz Forums 2000 SQL injection");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) 
	exit(0);

if(!get_port_state(port))
	exit(0);

url = "/forum/register.asp";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);
if( buf == NULL ) 
	exit(0);

# Ex: Powered By: Snitz Forums 2000 Version 3.4.03

#if("Powered By: Snitz Forums 2000 3.3.03" >< buf )
# jwl: per CVE, all version prior to 3.3.03 are vulnerable
if (egrep(string:buf, pattern:"Powered By: Snitz Forums 2000 ([0-2]\.*|3\.[0-2]\.*|3\.3\.0[0-2])"))
{
	security_message(port);
    	exit(0);
}


