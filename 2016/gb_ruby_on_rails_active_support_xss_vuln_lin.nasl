###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_on_rails_active_support_xss_vuln_lin.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# Ruby on Rails Active Support Cross Site Scripting Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807382");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2015-3226");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-10-13 15:29:55 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Ruby on Rails Active Support Cross Site Scripting Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Ruby on Rails and is
  prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to error in handling 
 'ActiveSupport::JSON.encode' method which can lead to an XSS attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to inject arbitrary web script or HTML via crafted parameters.

  Impact Level: Application");

  script_tag(name:"affected", value:"Ruby on Rails versions 3.x, 3.0.x,
  3.1.x, 3.2.x, 4.1.x before 4.1.11, 4.2.x before 4.2.2 on Linux");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails 4.2.2, 4.1.11 or later,
  For updates refer to http://rubyonrails.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2015/06/16/17");
  script_xref(name : "URL" , value : "https://groups.google.com/forum/message/raw?msg=rubyonrails-security/7VlB_pck3hU/3QZrGIaQW6cJ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ruby_rails_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("RubyOnRails/installed", "Host/runs_unixoide");
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

##Check for version 3.0.x, 3.1.x, 3.2.x
if(RubyonRailVer =~ "^(3.0|3.1|3.2)")
{
   fix = "4.2.2 or 4.1.11 ";
   VULN = TRUE;
}

## Check for version 4.1.x before 4.1.11
else if(RubyonRailVer =~ "^(4\.1)")
{
  if(version_is_less(version:RubyonRailVer, test_version:"4.1.11"))
  {
    fix = "4.1.11";
    VULN = TRUE;
  }
}

## Check for version 4.2.x before 4.2.2
else if(RubyonRailVer =~ "^(4\.2)")
{ 
  if(version_is_less(version:RubyonRailVer, test_version:"4.2.2"))
  { 
    fix = "4.2.2";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:RubyonRailVer, fixed_version:fix);
  security_message(port:RubyonRailPort, data:report);
  exit(0);
}