# OpenVAS Vulnerability Test
# $Id: mt-load_cgi.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Movable Type initialization script found
#
# Authors:
# Rich Walchuck (rich.walchuck at gmail.com)
#
# Copyright:
# Copyright (C) 2004 Rich Walchuck
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
 script_oid("1.3.6.1.4.1.25623.1.0.16169");
 script_version("$Revision: 6056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_name("Movable Type initialization script found");

 
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2004 Rich Walchuck");
 script_family("Web application abuses");
 script_require_ports("Services/www",80);
 script_dependencies("find_service.nasl");

 script_tag(name : "solution" , value : "Remove the mt-load.cgi script after installation.");
 script_tag(name : "summary" , value : "mt-load.cgi is installed by the Movable Type Publishing  
 Platform.");
 script_tag(name : "impact" , value : "Failure to remove mt-load.cgi could enable someone else to create
 a weblog in your Movable Type installation, and possibly gain access to your data.");

 script_tag(name:"solution_type", value:"Workaround");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

url = "/mt/mt-load.cgi";

if(is_cgi_installed_ka(item:url, port:port)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
