# OpenVAS Vulnerability Test
# $Id: xst_http_trace.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: http TRACE XSS attack
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
# Improvements re TRACK and RFP reference courtesy of <sullo@cirt.net>
# Improvements by rd - http_get() to get full HTTP/1.1 support, 
# security _warning() instead of security _hole(), slight re-phrasing
# of the description
# Fixes by Tenable:
#   - added CVE xref.
#
# Copyright:
# Copyright (C) 2003 E-Soft Inc.
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

if(description)
{
 script_id(11213);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_name("http TRACE XSS attack");
 script_cve_id("CVE-2004-2320","CVE-2003-1567");
 script_bugtraq_id(9506, 9561, 11604);
 
 script_summary("http TRACE XSS attack");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2003 E-Soft Inc.");
 script_family("Web application abuses");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value :
"Debugging functions are enabled on the remote HTTP server.

The remote webserver supports the TRACE and/or TRACK methods. TRACE and TRACK
are HTTP methods which are used to debug web server connections.   

It has been shown that servers supporting this method are subject to
cross-site-scripting attacks, dubbed XST for Cross-Site-Tracing, when
used in conjunction with various weaknesses in browsers. 

An attacker may use this flaw to trick your legitimate web users to give
him their credentials.");

 script_tag(name : "solution" , value : "Disable these methods.");

 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/867593");
 exit(0);
}


sol["apache"] = "
Solution: 
Add the following lines for each virtual host in your configuration file :

    RewriteEngine on
    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
    RewriteRule .* - [F]

See also http://httpd.apache.org/docs/current/de/mod/core.html#traceenable    
";

sol["iis"] = "
Solution: Use the URLScan tool to deny HTTP TRACE requests or to permit only the methods 
needed to meet site requirements and policy.";

sol["SunONE"] = '
Solution: Add the following to the default object section in obj.conf:
    <Client method="TRACE">
     AuthTrans fn="set-variable"
     remove-headers="transfer-encoding"
     set-headers="content-length: -1"
     error="501"
    </Client>

If you are using Sun ONE Web Server releases 6.0 SP2 or below, compile
the NSAPI plugin located at:
   http://sunsolve.sun.com/pub-cgi/retrieve.pl?doc=fsalert%2F50603';



#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);


if ( egrep(pattern:"^Server:.*IIS", string:banner) ) report = sol["iis"];
else if ( egrep(pattern:"^Server:.*Apache", string:banner) ) report = sol["apache"];
else if ( egrep(pattern:"^Server.*SunONE", string:banner) ) report = sol["SunONE"];

file = "/OpenVAS"+rand() + ".html";	# Does not exist

    cmd1 = http_get(item: file, port:port);
    cmd2 = cmd1;
    
    cmd1 = ereg_replace(pattern:"GET /", string:cmd1, replace:"TRACE /");
    cmd2 = ereg_replace(pattern:"GET /", string:cmd2, replace:"TRACK /");

    ua = egrep(pattern:"^User-Agent", string:cmd1);
 
    reply = http_keepalive_send_recv(port:port, data:cmd1, bodyonly:TRUE);
    if ( reply == NULL ) exit(0);
    if(egrep(pattern:"^TRACE "+file+" HTTP/1\.", string:reply))
    {
	if ( ua && ua >!< reply ) exit(0);
	security_message(port:port, data:report);
	exit(0);
    }
   
    reply = http_keepalive_send_recv(port:port, data:cmd2, bodyonly:TRUE);
    if(egrep(pattern:"^TRACK "+file+" HTTP/1\.", string:reply))
    {
       if ( ua && ua >!< reply ) exit(0);

       security_message(port:port, data:report);
    }
