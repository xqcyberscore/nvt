###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat/JBoss EJBInvokerServlet / JMXInvokerServlet (RMI over HTTP) Marshalled Object Remote Code Execution
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
  script_oid("1.3.6.1.4.1.25623.1.0.103811");
  script_bugtraq_id(57552, 62854);
  script_version("2019-07-03T05:37:39+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-0874", "CVE-2013-4810");
  script_name("Apache Tomcat/JBoss EJBInvokerServlet / JMXInvokerServlet (RMI over HTTP) Marshalled Object Remote Code Execution");
  script_tag(name:"last_modification", value:"2019-07-03 05:37:39 +0000 (Wed, 03 Jul 2019)");
  script_tag(name:"creation_date", value:"2013-10-15 10:27:36 +0200 (Tue, 15 Oct 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-13-229/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57552");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62854");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/28713/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/30211");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow an attacker to execute
  arbitrary code within the context of the affected application. Failed
  exploit attempts may result in a denial-of-service condition.");

  script_tag(name:"vuldetect", value:"Determine if the EJBInvokerServlet and/or JMXInvokerServlet is accessible without authentication.");

  script_tag(name:"insight", value:"The specific flaw exists within the exposed EJBInvokerServlet and JMXInvokerServlet. An unauthenticated
  attacker can post a marshalled object allowing them to install an arbitrary application on the target server.");

  script_tag(name:"solution", value:"Ask the Vendor for an update and enable authentication for the mentioned servlets.");

  script_tag(name:"summary", value:"Apache Tomcat/JBoss Application Server is prone to multiple remote code-
  execution vulnerabilities.");

  script_tag(name:"affected", value:"Apache Tomcat/JBoss Application Server providing access to the EJBInvokerServlet and/or JMXInvokerServlet
  without prior authentication.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:9200);

report = 'The following Servlets are accessible without authentication which indicates that a RCE attack can be executed:\n';

foreach file(make_list("/EJBInvokerServlet", "/JMXInvokerServlet")) {

  url = "/invoker" + file;
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req);

  if(buf =~ "^HTTP/1\.[01] 200" &&
     "404" >!< buf &&
     "org.jboss.invocation.MarshalledValue" >< buf &&
     "x-java-serialized-object" >< buf &&
     "WWW-Authenticate" >!< buf) {

    report += '\n' + report_vuln_url(port:port, url:url, url_only:TRUE);
    VULN = TRUE;
  }
}

if(VULN) {
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
