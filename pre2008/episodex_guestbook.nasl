# OpenVAS Vulnerability Test
# $Id: episodex_guestbook.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: Episodex Guestbook Unauthorized Access and HTML Injection Vulnerability
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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

tag_summary = "The remote host is running the Episodex Guestbook, a guestbook written in ASP.

The remote version of this software contains an input validation flaw leading
to the execution on attacker supplied HTML and script code. In addition an
unauthenticated remote attacker can directly access administrator functions.";

tag_solution = "None at this time";

if(description)
{
 script_id(18362);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_cve_id("CVE-2005-1684");
 script_bugtraq_id(13692, 13693);

 name = "Episodex Guestbook Unauthorized Access and HTML Injection Vulnerability";
 script_name(name);


 summary = "Checks for unathentication access to admin.asp";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");

 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

function check(url)
{
 req = http_get(item:url +"/admin.asp", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( 'Save Configuration' >< res && 'powered by Sven Moderow\'s GuestBook' >< res )
 {
        security_message(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
  check(url:dir);


