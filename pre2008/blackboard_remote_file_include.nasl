# OpenVAS Vulnerability Test
# $Id: blackboard_remote_file_include.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: BlackBoard Internet Newsboard System remote file include flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

tag_summary = "The remote host is running the BlackBoard Internet Newsboard System,
an open-source PHP-based internet bulletin board software.

The remote version of this software is vulnerable to a remote file
include flaw due to a lack of sanitization of user-supplied data.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server.

*** OpenVAS reports this vulnerability using only
*** information that was gathered. Therefore,
*** this might be a false positive.";

tag_solution = "Upgrade to the newest version of this software";

# Ref: Lin Xiaofeng <Cracklove@Gmail.Com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15450");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1582");
  script_bugtraq_id(11336);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BlackBoard Internet Newsboard System remote file include flaw");

 

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port))exit(0);

if(get_port_state(port))
{
  buf = http_get(item:"/forum.php", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<title>BlackBoard Internet Newsboard System</title>.*BlackBoard.*(0\.|1\.([0-4]|5[^.]|5\.1[^-]|5\.1-[a-g]))", string:r))
  {
    security_message(port);
  }
}
exit(0);
