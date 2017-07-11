###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mediawiki_login_csrf_vuln.nasl 6284 2017-06-06 11:43:39Z cfischer $
#
# MediaWiki Login CSRF Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901109");
  script_version("$Revision: 6284 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-06 13:43:39 +0200 (Tue, 06 Jun 2017) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-1150");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("MediaWiki Login CSRF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mediawiki/installed");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=580418");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=23076");

  tag_impact = "Successful exploitation will let the attacker cause CSRF attack and gain
  sensitive information.

  Impact Level: Application";

  tag_affected = "MediaWiki version prior to 1.15.3

  MediaWiki version prior to 1.16.0beta2";

  tag_insight = "The flaw is caused by improper validation of authenticated but unintended
  login attempt that allows attacker to conduct phishing attacks.";

  tag_solution = "Upgrade to the latest version of MediaWiki 1.15.3 or later,
  For updates refer tohttp://www.mediawiki.org";

  tag_summary = "This host is running MediaWiki and is prone to Login CSRF vulnerability.";

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

if( version_is_less( version:vers, test_version:"1.15.3" ) ||
    version_in_range( version:vers, test_version:"1.6", test_version2:"1.16.0.beta1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.15.3 or 1.16.0.beta2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );