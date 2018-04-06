# OpenVAS Vulnerability Test
# $Id: mambo_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Mambo Site Server 4.0.10 XSS
#
# Authors:
# K-Otik.com <ReYn0@k-otik.com>
# Updated: 04/07/2009
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2003 k-otik.com
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

tag_summary = "An attacker may use the installed version of Mambo Site Server to
  perform a cross site scripting attack on this host.";

tag_solution = "Upgrade to a newer version.";

#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns </archive/1/315554/2003-03-19/2003-03-25/1>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11441");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1203");
  script_bugtraq_id(7135);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Mambo Site Server 4.0.10 XSS");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2003 k-otik.com");
  script_dependencies("mambo_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){
  exit(0);
}

version=get_kb_item(string("www/", port, "/mambo_mos"));
if(!version){
   exit(0);
}

matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$");
if(!imatches){
  exit(0);
}

dir = matches[2];
url = string(dir, "/index.php?option=search&searchword=<script>alert(document.cookie);</script>");
req = http_get(item:url, port:port);
resp = http_keepalive_send_recv(port:port, data:req);
if(!resp){
  exit(0);
}

if(resp =~ "HTTP/1\.. 200" && "<script>alert(document.cookie);</script>" >< resp)
  security_message(port);

