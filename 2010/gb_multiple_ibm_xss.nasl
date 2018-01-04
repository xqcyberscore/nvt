###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_ibm_xss.nasl 8269 2018-01-02 07:28:22Z teissa $
#
# Multiple IBM Products Login Page Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
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

tag_summary = "Multiple IBM products are prone to a cross-site scripting
vulnerability because it fails to properly sanitize user-
supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

This issue affects IBM Lotus Web Content Management, WebSphere Portal,
and Lotus Quickr.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100538");
 script_version("$Revision: 8269 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-17 13:20:23 +0100 (Wed, 17 Mar 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2010-0714");
 script_bugtraq_id(38412);

 script_name("Multiple IBM Products Login Page Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38412");
 script_xref(name : "URL" , value : "http://www.hacktics.com/#view=Resources%7CAdvisory");
 script_xref(name : "URL" , value : "http://www-306.ibm.com/software/lotus/products/quickr/");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/software/lotus/products/webcontentmanagement/");
 script_xref(name : "URL" , value : "http://www-306.ibm.com/software/websphere/portal/");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21421469");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 10040);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:10040);
if(!get_port_state(port))exit(0);

dir = "/wps/wcm/webinterface/login";

url = string(dir,"/login.jsp?%22%3E%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E"); 
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);  
if( buf == NULL )continue;

if(buf =~ "HTTP/1\.. 200" && egrep(pattern: "<script>alert\('openvas-xss-test'\)</script>", string: buf, icase: TRUE)) {
   
  security_message(port:port);
  exit(0);

}

exit(0);

