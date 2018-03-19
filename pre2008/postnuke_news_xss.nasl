##############################################################################
# OpenVAS Vulnerability Test
# $Id: postnuke_news_xss.nasl 9126 2018-03-17 16:19:49Z cfischer $
#
# Post-Nuke News module XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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
##############################################################################

#  Ref: Muhammad Faisal Rauf Danka   <mfrd@attitudex.com> - Gem Internet Services (Pvt) Ltd.

CPE = "cpe:/a:postnuke:postnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14727");
  script_version("$Revision: 9126 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-17 17:19:49 +0100 (Sat, 17 Mar 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5809);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Post-Nuke News module XSS");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_dependencies("secpod_zikula_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("postnuke/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5809");

  tag_summary = "The remote host is running a version of Post-Nuke which contains
  the 'News' module which itself is vulnerable to a cross site scripting issue.";

  tag_impact = "An attacker may use these flaws to steal the cookies of the
  legitimate users of this web site.";

  tag_solution = "Upgrade to the latest version of postnuke.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );

ver = infos['version'];
dir = infos['location'];

if( ! safe_checks() ) {
  url = dir + "/modules.php?op=modload&name=News&file=article&sid=<script>foo</script>";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( res =~ "^HTTP/1\.[01] 200" && "<script>foo</script>" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( version_is_less_equal( version:ver, test_version:"0.721" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"See references." );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );