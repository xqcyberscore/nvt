###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dokuwiki_php_info_disc_vuln.nasl 5145 2017-01-31 11:07:58Z cfi $
#
# DokuWiki '.php' Files Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902734");
  script_version("$Revision: 5145 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 12:07:58 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_cve_id("CVE-2011-3727");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("DokuWiki '.php' Files Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2011-3727");
  script_xref(name:"URL", value:"https://www.infosecisland.com/alertsview/16752-CVE-2011-3727-dokuwiki.html");
  script_xref(name:"URL", value:"http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/dokuwiki-2009-12-25c");

  tag_impact = "Successful exploitation will allow attacker to gain sensitive
  information.

  Impact Level: Application";

  tag_affected = "DokuWiki version 2009-12-25c.";

  tag_insight = "The flaw is due to error in certain '.php' files. A direct
  request to these files reveals the installation path in an error message.";

  tag_solution = "Upgrade to DokuWiki version dokuwiki-20121013 or later.
  For updates refer to http://www.splitbrain.org/projects/dokuwiki";

  tag_summary = "The host is running DokuWiki and is prone to information
  disclosure vulnerability.";

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

url = dir + "/lib/tpl/index.php";

## Try attack and check the response to confirm vulnerability.
if( http_vuln_check( port:port, url:url, pattern:"<b>Warning</b>:  define\(\)" +
                     " expects at least 2 parameters.*lib/tpl/index.php" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );