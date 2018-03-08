###############################################################################
# OpenVAS Vulnerability Test
# $Id: multiple_EditeurScripts_products_xss.nasl 9040 2018-03-07 11:52:54Z cfischer $
#
# Multiple EditeurScripts Products 'msg' Parameter Cross Site Scripting Vulnerability
#
# Authors:
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100049");
  script_version("$Revision: 9040 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-07 12:52:54 +0100 (Wed, 07 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6868");
  script_bugtraq_id(34112);
  script_name("Multiple EditeurScripts Products 'msg' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34112/discuss");

  tag_summary = "Multiple EditeurScripts products are prone to a cross-site scripting
  vulnerability because they fail to sufficiently sanitize
  user-supplied data.";

  tag_impact = "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks.";

  tag_affected ="The following products and versions are affected:

  -EScontacts v1.0

  -EsBaseAdmin v2.1

  -EsPartenaires v1.0

  -EsNews v1.2

  Other versions may also be affected.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

dir = make_list( "/EsContacts","/EsBaseAdmin/default","/EsPartenaires","/EsNews/admin/news" );
x = 0;

foreach d( dir ) {

  site = "/login.php";

  if( d == "/EsNews/admin/news" ) {
    site = "/modifier.php";
  }

  url = string( d, site, '?msg=<script>alert(document.cookie);</script>' );
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( buf == NULL ) continue;

  if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<script>alert\(document\.cookie\);</script>", string:buf ) ) {
    es_soft = eregmatch( string:d, pattern:"/([a-zA-Z]+)/*.*" );
    if( ! isnull( es_soft[1] ) ) {
      vuln_essoft_found[x] = es_soft[1];
    }
  }
  x++;
}

if( vuln_essoft_found ) {
  info = string( "The following vulnerable EditeurScripts products were detected on the remote host:\n\n" );
  foreach found( vuln_essoft_found ) {
    if( ! isnull( found ) ) {
      vuln = TRUE;
      info += string("  ",found,"\n");
    }
  }

  if( vuln ) {
    security_message( port:port, data:info );
    exit( 0 );
  }
}

exit( 99 );
