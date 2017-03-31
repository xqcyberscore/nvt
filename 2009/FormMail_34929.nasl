###############################################################################
# OpenVAS Vulnerability Test
# $Id: FormMail_34929.nasl 4824 2016-12-21 08:49:38Z teissa $
#
# Matt Wright FormMail HTTP Response Splitting and Cross Site
# Scripting Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "FormMail is prone to an HTTP-response-splitting vulnerability and
  multiple cross-site scripting vulnerabilities because it fails to
  properly sanitize user-supplied input.

  An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user, steal cookie-based
  authentication credentials, and influence how web content is served,
  cached, or interpreted. This could aid in various attacks that try
  to entice client users into a false sense of trust.

  These issues affect FormMail 1.92; prior versions may also be
  affected.";


if (description)
{
 script_id(100202);
 script_version("$Revision: 4824 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-21 09:49:38 +0100 (Wed, 21 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-05-14 20:19:12 +0200 (Thu, 14 May 2009)");
 script_cve_id("CVE-2009-1776");
 script_bugtraq_id(34929);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Matt Wright FormMail HTTP Response Splitting and Cross Site Scripting Vulnerabilities");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("FormMail_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34929");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("www/", port, "/FormMail")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "1.92")) {
      security_message(port:port);
      exit(0);
  }  

} else {

 if(isnull(dir))exit(0); 
 if(! file = get_kb_item(string("www/", port, "/FormMail/file")))exit(0);

 hostnames = make_list("localhost",get_host_name());

 foreach hostname (hostnames) {

   request = string("/",file,"?recipient=foobar@",hostname,"&subject=1&return_link_url=javascript:alert(0815)&return_link_title=OpenVAS-Test");

   url = string(dir, request); 
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
   if( buf == NULL ) continue;

   if(buf =~ "HTTP/1\.. 200" && egrep(pattern: "<a href=.javascript:alert\(0815\).>OpenVAS-Test</a>", string: buf)) {

      security_message(port:port);
      exit(0);

   }
 }
}

exit(0);
