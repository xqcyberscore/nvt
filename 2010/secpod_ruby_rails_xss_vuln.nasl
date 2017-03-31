###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_rails_xss_vuln.nasl 5401 2017-02-23 09:46:07Z teissa $
#
# Ruby on Rails 'unicode strings' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

CPE = 'cpe:/a:rubyonrails:ruby_on_rails';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902090");
  script_version("$Revision: 5401 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-23 10:46:07 +0100 (Thu, 23 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-3009");
  script_bugtraq_id(36278);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ruby on Rails 'unicode strings' Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl", "gb_ruby_rails_detect.nasl");
  script_mandatory_keys("RubyOnRails/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53036");
  script_xref(name:"URL", value:"http://secunia.com/advisories/product/25856/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2544");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Sep/1022824.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.

  Impact Level: Application");
  script_tag(name:"affected", value:"Ruby on Rails version 2.x before to 2.2.3 and 2.3.x before 2.3.4");
  script_tag(name:"insight", value:"The flaw is due to error in handling of 'escaping' code for the form
  helpers, which does not properly filter HTML code from user-supplied input
  before displaying the input.");
  script_tag(name:"solution", value:"Upgrade to Ruby on Rails version 2.2.3 or 2.3.4 or later.
  For updates refer to http://rubyonrails.org/download");
  script_tag(name:"summary", value:"This host is running Ruby on Rails and is prone to cross-site
  scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Check Ruby on Rails version
if(version_in_range( version:vers, test_version:"2.0", test_version2:"2.2.2" ) ||
   version_in_range( version:vers, test_version:"2.3.0", test_version2:"2.3.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.3/2.3.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );