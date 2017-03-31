# OpenVAS Vulnerability Test
# $Id: 404_path_disclosure.nasl 3398 2016-05-30 07:58:00Z antu123 $
# Description: Non-Existant Page Physical Path Disclosure Vulnerability
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

tag_summary = "Your web server reveals the physical path of the webroot 
when asked for a non-existent page.

Whilst printing errors to the output is useful for debugging applications, 
this feature should not be enabled on production servers.";

tag_solution = "Upgrade your server or reconfigure it";

# Vulnerable servers:
# Pi3Web/2.0.0
#
# References
# Date:  10 Mar 2002 04:23:45 -0000
# From: "Tekno pHReak" <tek@superw00t.com>
# To: bugtraq@securityfocus.com
# Subject: Pi3Web/2.0.0 File-Disclosure/Path Disclosure vuln
#
# Date:	 Wed, 14 Aug 2002 23:40:55 +0400
# From:	"D4rkGr3y" <grey_1999@mail.ru>
# To:	bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: new bugs in MyWebServer

if(description)
{
 script_id(11714);
 script_version("$Revision: 3398 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-30 09:58:00 +0200 (Mon, 30 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3341, 4035, 4261, 5054, 8075);
 # Note: the way the test is made will lead to detecting some
 # path disclosure issues which might be checked by other plugins 
 # (like #11226: Oracle9i jsp error). I have reviewed the reported
 # "path disclosure" errors from bugtraq and the following list
 # includes bugs which will be triggered by the NASL script. Some
 # other "path disclosure" bugs in webservers might not be triggered
 # since they might depend on some specific condition (execution
 # of a cgi, options..)
 # jfs - December 2003
 script_cve_id("CVE-2003-0456","CVE-2001-1372");
 
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "Non-Existant Page Physical Path Disclosure Vulnerability";

 script_name(name);
 

 summary = "Tests for a Generic Physical Path Disclosure Vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# 

include("http_func.inc");
include("http_keepalive.inc");

ext = make_list(".", "/", ".html", ".htm", ".jsp", ".asp", ".shtm", ".shtml",
		".php", ".php3", ".php4", ".cfm");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

foreach e (ext)
{
  f = string("niet", rand());
  req = http_get(item:string("/", f, e), port:port);
  r = http_keepalive_send_recv(port: port, data: req);
  if(isnull(r)) exit(0);	# Connection refused
  # Windows-like path
  if (egrep(string: r, pattern: strcat("[C-H]:(\\[A-Za-z0-9_.-])*\\", f, "\\", e)))
  {
    security_message(port);
    exit(0);
   }
  # Unix like path
  if (egrep(string: r, pattern: strcat("(/[A-Za-z0-9_.+-])+/", f, "/", e)))
  {
    security_message(port);
    exit(0);
   }
}
