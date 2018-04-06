###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_race_cond_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Ruby 'FileUtils.remove_entry_secure()' Method Race Condition Vulnerability
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

tag_impact = "Successful exploitation allows attackers to execute arbitrary code with
  elevated privileges or cause a denial-of-service condition.
  Impact Level: Application.";
tag_affected = "Ruby version 1.8.6 through 1.8.6 patchlevel 420

  Ruby version 1.8.7 through 1.8.7 patchlevel 330

  Ruby version 1.9.1 through 1.9.1 patchlevel 430

  Ruby version 1.9.2 through 1.9.2 patchlevel 136

  Ruby version 1.9.3dev, 1.8.8dev";

tag_insight = "The flaw is due to a race condition within the
  'FileUtils.remove_entry_secure' method, which can be exploited to delete
  arbitrary directories and files via symlink attacks.";
tag_solution = "Upgrade to Ruby version 1.8.7-334 or 1.9.1-p431 or 1.9.2-p180 or later
  For updates refer to http://rubyforge.org/frs/?group_id=167";
tag_summary = "This host is installed with Ruby and is prone to race condition
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801759");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1004");
  script_bugtraq_id(46460);
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_name("Ruby 'FileUtils.remove_entry_secure()' Method Race Condition Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43434");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=678913");
  script_xref(name : "URL" , value : "http://www.ruby-lang.org/en/news/2011/02/18/fileutils-is-vulnerable-to-symlink-race-attacks/");

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
    version_in_range( version:vers, test_version:"1.9.1", test_version2:"1.9.1.p430" ) ||
    version_in_range( version:vers, test_version:"1.9.2", test_version2:"1.9.2.p136" ) ||
    version_is_equal( version:vers, test_version:"1.9.3" ) ||
    version_is_equal( version:vers, test_version:"1.8.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.7-334 / 1.9.1-p431 / 1.9.2-p180", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );