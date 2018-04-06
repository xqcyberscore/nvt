# OpenVAS Vulnerability Test
# $Id: novell_groupwise_servletmanager_default_password.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Novell Groupwise Servlet Manager default password
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2004 David Kyger
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

tag_summary = "The Novell Groupwise servlet server is configured with the default password.
As a result, users could be denied access to mail and other servlet
based resources.

To test this finding:

https://<host>/servlet/ServletManager/ 

enter 'servlet' for the user and 'manager' for the password.";

tag_solution = "Change the default password

Edit SYS:\JAVA\SERVLETS\SERVLET.PROPERTIES

change the username and password in this section
servlet.ServletManager.initArgs=datamethod=POST,user=servlet,password=manager,bgcolor";


if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.12122");
    script_version("$Revision: 9348 $");
    script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_bugtraq_id(3697);
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_cve_id("CVE-2001-1195");
    name = "Novell Groupwise Servlet Manager default password";
    script_name(name);

    summary = "Checks for Netware servlet server default password";


    script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");

    script_copyright("This script is Copyright (C) 2004 David Kyger");

    family = "Netware";
    script_family(family);
    script_dependencies("find_service.nasl", "http_version.nasl");
    script_require_ports("Services/www", 443);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/3697");
    exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

warning = string("
The Novell Groupwise servlet server is configured with the default password.
As a result, users could be denied access to mail and other servlet
based resources.

To test this finding:

https://<host>/servlet/ServletManager/

enter 'servlet' for the user and 'manager' for the password.

Solution: Change the default password

Edit SYS:\\JAVA\\SERVLETS\\SERVLET.PROPERTIES

change the username and password in this section
servlet.ServletManager.initArgs=datamethod=POST,user=servlet,password=manager,bgcolor

See also: http://www.securityfocus.com/bid/3697");



port = get_http_port(default:443);

req = string("GET /servlet/ServletManager HTTP/1.1\r\nHost: ", get_host_name(), "\r\nAuthorization: Basic c2VydmxldDptYW5hZ2Vy\r\n\r\n");

buf = http_keepalive_send_recv(port:port, data:req);
if ( buf == NULL ) exit(0);

pat1 = "ServletManager"; 
pat2 = "Servlet information";


    if(pat1 >< buf && pat2 >< buf)
    {
        security_message(port:port, data:warning);
    }
