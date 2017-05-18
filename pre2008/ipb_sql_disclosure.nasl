# OpenVAS Vulnerability Test
# $Id: ipb_sql_disclosure.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: SQL Disclosure in Invision Power Board
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

tag_summary = "There is a vulnerability in the current version of Invision Power Board
that allows an attacker to reveal the SQL queries used by the product, and
any page that was built by the administrator using the IPB's interface,
simply by appending the variable 'debug' to the request.";

tag_solution = "Upgrade to the newest version of this software.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.12648";
CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  name = "SQL Disclosure in Invision Power Board";
  script_name(name);
 

 
  summary = "Detect IPB SQL Disclosure";
 
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

  family = "Web application abuses";
  script_family(family);
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("invision_power_board/installed");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if (! port) exit(0);

if(!path = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

req = http_get(item:string(path, "/?debug=whatever"), port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

find = string("SQL Debugger");
find2 = string("Total SQL Time");
find3 = string("mySQL time");

if (find >< res || find2 ><  res || find3 >< res )
{
 security_message(port);
 exit(0);
}



