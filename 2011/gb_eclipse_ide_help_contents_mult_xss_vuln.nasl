##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eclipse_ide_help_contents_mult_xss_vuln.nasl 7029 2017-08-31 11:51:40Z teissa $
#
# Eclipse IDE Help Contents Multiple Cross-site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801746");
  script_version("$Revision: 7029 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-31 13:51:40 +0200 (Thu, 31 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-7271");
  script_name("Eclipse IDE Help Contents Multiple Cross-site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://r00tin.blogspot.com/2008/04/eclipse-local-web-server-exploitation.html");

  tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected application.

  Impact Level: Application.";

  tag_affected = "Eclipse IDE Version 3.3.2";

  tag_insight = "- Input passed to the 'searchWord' parameter in 'help/advanced/searchView.jsp' and
  'workingSet' parameter in 'help/advanced/workingSetManager.jsp' are not
  properly sanitised before being returned to the user.";

  tag_solution = "Upgrade to Eclipse IDE Version 3.6.2 or later
  For updates refer to http://www.eclipse.org/downloads/";

  tag_summary = "This host is running Eclipse IDE is prone to multiple Cross-Site
  Scripting vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

## Listens on the ports in the range 900-70000
port = get_http_port( default:80 );

rcvRes = http_get_cache( item:"/help/index.jsp", port:port );

## Confirm the application
if( "<title>Help - Eclipse" >< rcvRes ) {

  url = '/help/advanced/searchView.jsp?searchWord=a");}alert' +
        '("OpenVAS-XSS-Testing");</script>';
  sndReq = http_get( item:url, port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  ## Check the response to confirm vulnerability
  if( rcvRes =~ "HTTP/1\.. 200" && 'alert("OpenVAS-XSS-Testing");</script>' >< rcvRes ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit( 0 );