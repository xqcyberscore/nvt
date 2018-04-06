###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_sec_bypass_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Ruby "#to_s" Security Bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ruby-lang:ruby";

tag_impact = "Successful exploitation allows attackers to bypass certain security
  restrictions and perform unauthorized actions.
  Impact Level: Application.";
tag_affected = "Ruby version 1.8.6 through 1.8.6 patchlevel 420

  Ruby version 1.8.7 through 1.8.7 patchlevel 330

  Ruby version 1.8.8dev";

tag_insight = "The flaw is due to the error in 'Exception#to_s' method, which trick
  safe level mechanism and destructively modifies an untaitned string to be
  tainted.";
tag_solution = "Upgrade to Ruby version 1.8.7-334 or later
  For updates refer to http://rubyforge.org/frs/?group_id=167";
tag_summary = "This host is installed with Ruby and is prone to security bypass
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801760");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1005");
  script_bugtraq_id(46458);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Ruby '#to_s' Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=678920");
  script_xref(name : "URL" , value : "http://www.ruby-lang.org/en/news/2011/02/18/exception-methods-can-bypass-safe/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ruby_detect_win.nasl");
  script_mandatory_keys("Ruby/Win/Installed");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

# Grep for Ruby version
if( version_in_range( version:vers, test_version:"1.8.6", test_version2:"1.8.6.p420" ) ||
    version_in_range( version:vers, test_version:"1.8.7", test_version2:"1.8.7.p330" ) ||
    version_is_equal( version:vers, test_version:"1.8.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.7-334", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );