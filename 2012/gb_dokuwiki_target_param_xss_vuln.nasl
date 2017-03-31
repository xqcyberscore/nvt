##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_target_param_xss_vuln.nasl 5145 2017-01-31 11:07:58Z cfi $
#
# DokuWiki 'target' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803008");
  script_version("$Revision: 5145 $");
  script_cve_id("CVE-2012-2129");
  script_bugtraq_id(53041);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 12:07:58 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2012-08-28 11:26:53 +0530 (Tue, 28 Aug 2012)");
  script_name("DokuWiki 'target' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48848");
  script_xref(name:"URL", value:"http://ircrash.com/uploads/dokuwiki.txt");
  script_xref(name:"URL", value:"https://bugs.dokuwiki.org/index.php?do=details&task_id=2487");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111939/DocuWiki-2012-01-25-Cross-Site-Request-Forgery-Cross-Site-Scripting.html");

  tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.

  Impact Level: Application";

  tag_affected = "DokuWiki version 2012-01-25 and prior";

  tag_insight = "The input passed via 'target' parameter to 'doku.php' script (when 'do' is
  set to 'edit') is not properly validated, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.";

  tag_solution = "Upgrade to DokuWiki version 2012-01-25a or later
  For updates refer to http://www.splitbrain.org/projects/dokuwiki";

  tag_summary = "This host is running DokuWiki and is prone to cross site scripting
  vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

url = dir + "/doku.php?do=edit&id=S9F8W2A&target=<script>alert"+
            "(document.cookie);</script>";

if( http_vuln_check( port:port, url:url,
                     pattern:"<script>alert\(document.cookie\);</script>", check_header:TRUE,
                     extra_check:'content="DokuWiki"/>' ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );