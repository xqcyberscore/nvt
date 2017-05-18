# OpenVAS Vulnerability Test
# $Id: savant_cgi_download.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Savant original form CGI access
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10623");
 script_version("$Revision: 6056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1313);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2000-0521");
 script_name("Savant original form CGI access");

 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("gb_get_http_banner.nasl", "no404.nasl");

 script_require_keys("www/apache","Savant/banner");
 script_require_ports("Services/www", 80);

 script_tag(name : "solution" , value : "A security vulnerability in the Savant web server allows attackers to download the original form of CGIs (unprocessed).
 This would allow them to see any sensitive information stored inside those CGIs.");
 script_tag(name : "summary" , value : "The newest version is still vulnerable to attack (version 2.1), it would be recommended that users cease to use this product.

 Additional information:
 http://www.securiteam.com/exploits/Savant_Webserver_exposes_CGI_script_source.html");

 script_tag(name:"solution_type", value:"WillNotFix");
 script_tag(name:"qod_type", value:"remote_active");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);

if ("Server: Savant/">< banner) {

  foreach dir (make_list_unique("/", cgi_dirs(port:port))) {

    if(dir == "/") dir = "";

    if (is_cgi_installed_ka(port:port, item:string(dir, "/cgitest.exe"))) {

      data = http_get(item:string(dir, "/cgitest.exe"), port:port);

      soctcp80 = http_open_socket(port);
      resultsend = send(socket:soctcp80, data:data);
      resultrecv = http_recv(socket:soctcp80);
      http_close_socket(soctcp80);
      if ((resultrecv[0] == string("M")) && (resultrecv[1] == string("Z"))) {
        security_message(port:port);
        exit(0);
      } else {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
