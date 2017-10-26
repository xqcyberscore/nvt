###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ruby_on_rails_action_record_sql_inj_vuln_win.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# Ruby on Rails Active Record SQL Injection Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807377");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-6317");
  script_bugtraq_id(92434);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-10-13 14:29:34 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Ruby on Rails Active Record SQL Injection Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Ruby on Rails and is
  prone to SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to the way Active Record
  interprets parameters in combination with the way that JSON parameters are
  parsed, it is possible for an attacker to issue unexpected database queries
  with 'IS NULL' or empty where clauses.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass intended database-query restrictions and perform NULL checks
  or trigger missing WHERE clauses via a crafted request, as demonstrated by
  certain '[nil]' values.

  Impact Level: Application");

  script_tag(name:"affected", value:"Ruby on Rails 4.2.x before 4.2.7.1 on Windows");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails 4.2.7.1 or later.
  For updates refer to http://rubyonrails.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2016/08/11/4");
  script_xref(name : "URL" , value : "https://groups.google.com/forum/#!topic/ruby-security-ann/WccgKSKiPZA");
  script_xref(name : "URL" , value : "http://weblog.rubyonrails.org/2016/8/11/Rails-5-0-0-1-4-2-7-2-and-3-2-22-3-have-been-released");
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

##Check for vulnerable version
if(version_in_range(version:RubyonRailVer, test_version:"4.2.0", test_version2:"4.2.7.0"))
{
  report = report_fixed_ver(installed_version:RubyonRailVer, fixed_version:"4.2.7.1");
  security_message(data:report, port:RubyonRailPort);
  exit(0);
}