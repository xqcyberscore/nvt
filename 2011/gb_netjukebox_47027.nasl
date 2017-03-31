###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netjukebox_47027.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# netjukebox 'skin' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "netjukebox is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input before using it in
dynamically generated content.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

netjukebox 5.25 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103126);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-03-25 13:20:06 +0100 (Fri, 25 Mar 2011)");
 script_bugtraq_id(47027);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("netjukebox 'skin' Parameter Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47027");
 script_xref(name : "URL" , value : "http://www.netjukebox.nl/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if netjukebox is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/netjukebox",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,'/message.php?skin="><script>alert(/openvas-xss-test/)</script>'); 

  if(http_vuln_check(port:port,url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",extra_check:"Message has expired",check_header:TRUE)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
