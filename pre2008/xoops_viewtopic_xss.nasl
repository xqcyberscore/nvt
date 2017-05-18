###############################################################################
# OpenVAS Vulnerability Test
# $Id: xoops_viewtopic_xss.nasl 5952 2017-04-13 12:34:17Z cfi $
#
# XOOPS viewtopic.php Cross Site Scripting Vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on Noam Rathaus script
# Updated: 05/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

#  Ref: Ben Drysdale <ben@150bpm.co.uk>

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15480");
  script_version("$Revision: 5952 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-13 14:34:17 +0200 (Thu, 13 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2756");
  script_bugtraq_id(9497);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("XOOPS viewtopic.php Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2004/Jan/1008849.html");

  tag_summary = "The remote web server contains a PHP script that is prone to cross-
  site scripting attacks.";

  tag_insight = "The weblinks module of XOOPS contains a file named 'viewtopic.php' in
  the '/modules/newbb' directory. The code of the module insufficently filters out user
  provided data.";

  tag_impact = "The URL parameter used by 'viewtopic.php' can be used to insert malicious
  HTML and/or JavaScript in to the web page.";

  tag_solution = "Unknown at this time.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + '/modules/newbb/viewtopic.php?topic_id=14577&forum=2\"><script>foo</script>';
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "HTTP/1\.[0-1] 200" && "<script>foo</script>" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );