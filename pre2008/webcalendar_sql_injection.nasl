# OpenVAS Vulnerability Test
# $Id: webcalendar_sql_injection.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: WebCalendar SQL Injection
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

tag_summary = "The remote installation of WebCalendar may allow an attacker to cause
an SQL Injection vulnerability in the program allowing an attacker to
cause the program to execute arbitrary SQL statements.";

if(description)
{
 script_id(15752);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id(
   "CVE-2004-1506",
   "CVE-2004-1507",
   "CVE-2004-1508",
   "CVE-2004-1509",
   "CVE-2004-1510"
 );
 script_bugtraq_id(11651);
 
 name = "WebCalendar SQL Injection";

 script_name(name);
 

 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("webcalendar_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("webcalendar/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 req = http_get(item:string(loc, "/view_entry.php?id=1'&date=1"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL )exit(0);
 if(egrep(pattern:"You have an error in your SQL syntax", string:r) ||
    egrep(pattern:"SELECT webcal_entry.cal_id FROM webcal_entry", string: r)
   )
 {
 	security_message(port);
	exit(0);
 }
}
