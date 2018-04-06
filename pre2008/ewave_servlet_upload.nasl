# OpenVAS Vulnerability Test
# $Id: ewave_servlet_upload.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Unify eWave ServletExec 3.0C file upload
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2000 Matt Moore
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

tag_summary = "ServletExec has a servlet called 'UploadServlet' in its server
side classes. UploadServlet, when invokable, allows an
attacker to upload any file to any directory on the server. The
uploaded file may have code that can later be executed on the
server, leading to remote command execution.";

tag_solution = "Remove it";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10570");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1876);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-2000-1024");
 name = "Unify eWave ServletExec 3.0C file upload";
 script_name(name);
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"/servlet/openvas." + string(rand(),rand(), rand()), port:port);
if ( res ) exit(0);

res = is_cgi_installed_ka(item:"/servlet/com.unify.servletexec.UploadServlet", port:port);
if(res)
{
 security_message(port);
}

