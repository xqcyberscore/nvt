###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_mult_csrf_vuln.nasl 5145 2017-01-31 11:07:58Z cfi $
#
# DokuWiki Multiple Cross Site Request Forgery Vulnerabilities
#
# Authors:
# Rachana Shetty <srachan@secpod.com>
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

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800989");
  script_version("$Revision: 5145 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 12:07:58 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0289");
  script_name("DokuWiki Multiple Cross Site Request Forgery Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38205");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0150");
  script_xref(name:"URL", value:"http://bugs.splitbrain.org/index.php?do=details&task_id=1853");

  tag_impact = "Successful exploitation allows attackers to conduct cross site request
  forgery attacks via unknown vectors.

  Impact Level: Application.";

  tag_affected = "Dokuwiki versions prior to 2009-12-25c";

  tag_insight = "The flaws are due to error in 'ACL' Manager plugin (plugins/acl/ajax.php) that
  allows users to perform certain actions via HTTP requests without performing
  any validity checks.";

  tag_solution = "Update to version 2009-12-25c or later.
  For updates refer to http://www.splitbrain.org/go/dokuwiki";

  tag_summary = "This host is installed with Dokuwiki and is prone to multiple Cross
  Site Scripting vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
 
if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

# Check for version less then 2009-12-25c
if( version_is_less( version:vers, test_version:"2009-12-25c" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2009-12-25c" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );