###############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_Tomcat_Servlet_XSS.nasl 10862 2018-08-09 14:51:58Z cfischer $
#
# Apache Tomcat /servlet Cross Site Scripting
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
###############################################################################

CPE = "cpe:/a:apache:tomcat";

# Also covers BugtraqID: 5194 (same Advisory ID#: wp-02-0008)

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11041");
  script_version("$Revision: 10862 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-09 16:51:58 +0200 (Thu, 09 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(5193);
  script_cve_id("CVE-2002-0682");
  script_name("Apache Tomcat /servlet Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheTomcat/installed");

  script_tag(name:"summary", value:"The remote Apache Tomcat web server is vulnerable to a cross site scripting
  issue.

  Description :

  Apache Tomcat is the servlet container that is used in the official Reference
  Implementation for the Java Servlet and JavaServer Pages technologies.

  By using the /servlet/ mapping to invoke various servlets / classes it is
  possible to cause Tomcat to throw an exception, allowing XSS attacks, e.g:

  tomcat-server/servlet/org.apache.catalina.servlets.WebdavStatus/SCRIPTalert(document.domain)/SCRIPT
  tomcat-server/servlet/org.apache.catalina.ContainerServlet/SCRIPTalert(document.domain)/SCRIPT
  tomcat-server/servlet/org.apache.catalina.Context/SCRIPTalert(document.domain)/SCRIPT
  tomcat-server/servlet/org.apache.catalina.Globals/SCRIPTalert(document.domain)/SCRIPT

  (angle brackets omitted)");
  script_tag(name:"solution", value:"The 'invoker' servlet (mapped to /servlet/), which executes anonymous servlet
  classes that have not been defined in a web.xml file should be unmapped.

  The entry for this can be found in the /tomcat-install-dir/conf/web.xml file.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( get_http_has_generic_xss( port:port, host:host ) ) exit( 0 );

url = "/servlet/org.apache.catalina.ContainerServlet/<SCRIPT>alert(document.domain)</SCRIPT>";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

confirmed = string("<SCRIPT>alert(document.domain)</SCRIPT>");
confirmed_too = string("javax.servlet.ServletException");

if( ( confirmed >< res ) && ( confirmed_too >< res ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );