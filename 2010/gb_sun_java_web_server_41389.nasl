###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_web_server_41389.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Sun Java System Web Server Admin Interface Denial of Service Vulnerability
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

tag_summary = "Sun Java System Web Server is prone to a denial-of-service
vulnerability.

An attacker can exploit this issue to crash the effected application,
denying service to legitimate users.

Sun Java System Web Server 7.0 Update 7 is affected; other versions
may also be vulnerable.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100703");
 script_version("$Revision: 8296 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-07 12:47:04 +0200 (Wed, 07 Jul 2010)");
 script_bugtraq_id(41389);

 script_name("Sun Java System Web Server Admin Interface Denial of Service Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41389");
 script_xref(name : "URL" , value : "http://www.sun.com/software/products/web_srvr/home_web_srvr.xml");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_sun_java_sys_web_serv_detect.nasl");
 script_require_ports("Services/www", 8989);
 script_mandatory_keys("Sun/JavaSysWebServ/Ver","Sun/JavaSysWebServ/Port");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

if( get_kb_item("Sun/JavaSysWebServ/Ver") != "7.0"){
  exit(0);
}

port = get_http_port(default:8989);
if(!get_port_state(port))exit(0);

if(version = get_kb_item(string("Sun/JavaSysWebServ/",port,"/Ver"))) {

vers = str_replace(find:"U", string: version, replace:".");

  if(version_is_equal(version: vers, test_version: "7.0.7")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
