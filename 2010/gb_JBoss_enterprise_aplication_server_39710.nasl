###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_JBoss_enterprise_aplication_server_39710.nasl 4216 2016-10-05 11:05:57Z cfi $
#
# JBoss Enterprise Application Platform Multiple Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100610");
  script_version("$Revision: 4216 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-05 13:05:57 +0200 (Wed, 05 Oct 2016) $");
  script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
  script_bugtraq_id(39710);
  script_cve_id("CVE-2010-0738","CVE-2010-1428","CVE-2010-1429");
  script_name("JBoss Enterprise Application Platform Multiple Vulnerabilities");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("JBoss_enterprise_aplication_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jboss/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39710");
  script_xref(name:"URL", value:"http://www.jboss.org");

  tag_summary = "JBoss Enterprise Application Platform is prone to multiple
  vulnerabilities, including an information-disclosure issue and
  multiple authentication-bypass issues.";

  tag_impact = "An attacker can exploit these issues to bypass certain security
  restrictions to obtain sensitive information or gain unauthorized
  access to the application.";

  tag_solution = "Updates are available. Please see the references for details.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Get JBoss port set by JBoss_enterprise_aplication_server_detect.nasl
if( ! port = get_kb_item( "jboss/port" ) ) exit( 0 );

url = "/jmx-console";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( buf == NULL ) exit( 0 );

if( buf =~ "HTTP/1.. [2|3]00" ) exit( 0 );

url = "/jmx-console/checkJNDI.jsp";
host = http_host_name( port:port );

req = string( "PUT ", url, " HTTP/1.0\r\n",
	      "Host: ", host, "\r\n",
	      "\r\n" );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "HTTP/1.. 200" && ( "JNDI Check</title>" >< res  && "JNDI Checking for host" >< res ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
