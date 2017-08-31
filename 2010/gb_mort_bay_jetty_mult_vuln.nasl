###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mort_bay_jetty_mult_vuln.nasl 6831 2017-08-01 14:36:41Z cfischer $
#
# Mort Bay Jetty Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800286");
  script_version("$Revision: 6831 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-01 16:36:41 +0200 (Tue, 01 Aug 2017) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4609", "CVE-2009-4610", "CVE-2009-4611", "CVE-2009-4612");

  script_name("Mort Bay Jetty Multiple Vulnerabilities");

  script_xref(name: "URL" , value: "http://seclists.org/fulldisclosure/2009/Oct/319");
  script_xref(name: "URL" , value: "http://www.ush.it/team/ush/hack-jetty6x7x/jetty-adv.txt");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_jetty_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Jetty/installed");

  script_tag(name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary
HTML and script code in a user's browser session and execute arbitrary commands or overwrite files in the context
of an affected site.

Impact Level: Application.");

  script_tag(name: "affected", value: "Jetty version 6.0.0 to 7.0.0");

  script_tag(name: "insight", value: "Inputs passed to the query string to 'jsp/dump.jsp' and to Name or Value
parameter in 'Session Dump Servlet' is not properly sanitised before being returned to the user.");

  script_tag(name: "summary" , value: "This host is running Mort Bay Jetty and is prone to multiple
vulnerabilities.");

  script_tag(name: "solution" , value: "No solution or patch was made available for at least one year since
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.

A Workaround is to apply workaround from below link, http://seclists.org/fulldisclosure/2009/Oct/319");

  script_tag(name: "solution_type", value: "WillNotFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe :CPE))
  exit(0);

xss = '<script>alert(/openvas-xss-test/)</script>';
pattern = "<script>alert\(/openvas-xss-test/\)</script>";

urls = make_list("/jspsnoop/ERROR/",
                 "/jsp/dump.jsp?",
                 "/test/jsp/dump.jsp?",
                 "/jsp/expr.jsp?A=");

foreach url (urls) {
 url = url + xss;

 if(http_vuln_check(port: port, url: url, pattern: pattern)) {
   report = report_vuln_url(port: port, url: url);
   security_message(port: port, data: report);
   exit(0);
 }
}  

url = '/dump/';

if (http_vuln_check(port: port, url: url, pattern: "<th[^>]+>getPathTranslated:[^<]+</th><td>(/|[A-Z]:\\).*jetty",
                    check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
