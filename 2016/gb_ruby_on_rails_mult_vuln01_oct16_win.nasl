###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_on_rails_mult_vuln01_oct16_win.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# Ruby on Rails Multiple Vulnerabilities-01 Oct16 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809356");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-0752", "CVE-2016-0751", "CVE-2015-7576");
  script_bugtraq_id(81801, 81800, 81803);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value: "2016-10-17 18:48:40 +0530 (Mon, 17 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Ruby on Rails Multiple Vulnerabilities-01 Oct16 (Windows)");

  script_tag(name:"summary", value:"This host is running Ruby on Rails and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  - Directory traversal vulnerability in Action View.
  - The script 'actionpack/lib/action_dispatch/http/mime_type.rb' does not properly
    restrict use of the MIME type cache.
  - The http_basic_authenticate_with method in
    'actionpack/lib/action_controller/metal/http_authentication.rb' does not use a
    constant-time algorithm for verifying credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files by leveraging an application's unrestricted use
  of the render method, to cause a denial of service.

  Impact Level: Application");

  script_tag(name:"affected", value:"
  Ruby on Rails before 3.2.22.1,
  Ruby on Rails 4.0.x and 4.1.x before 4.1.14.1 and
  Ruby on Rails 4.2.x before 4.2.5.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails 3.2.22.1 or 4.1.14.1 or
  4.2.5.1, or later. For updates refer to http://rubyonrails.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2016/01/25/10");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("RubyOnRails/installed", "Host/runs_windows");
  script_require_ports("Services/www", 3000);
  exit(0);
}


##
### Code Starts Here
##

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
RubyonRailPort = "";
RubyonRailVer = "";

## Get HTTP Port
if(!RubyonRailPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!RubyonRailVer = get_app_version(cpe:CPE, port:RubyonRailPort)){
  exit(0);
}

##Check for version before 3.2.22.1
if(version_is_less(version:RubyonRailVer, test_version:"3.2.22.1"))
{
  fix = "3.2.22.1";
  VULN = TRUE;
}

## Check for version 4.0, 4.1 before 4.1.14.1
else if(RubyonRailVer =~ "^(4\.)")
{
  if(version_is_less(version:RubyonRailVer, test_version:"4.1.14.1"))
  {
    fix = "4.1.14.1";
    VULN = TRUE;
  }
}

## Check for version 4.2 before 4.2.5.1
else if(RubyonRailVer =~ "^(4\.2)")
{
  if(version_is_less(version:RubyonRailVer, test_version:"4.2.5.1"))
  {
    fix = "4.2.5.1";
    VULN = TRUE;
  }
}

##Beta versions not considered

if(VULN)
{
  report = report_fixed_ver(installed_version:RubyonRailVer, fixed_version:fix);
  security_message(port:RubyonRailPort, data:report);
  exit(0);
}
