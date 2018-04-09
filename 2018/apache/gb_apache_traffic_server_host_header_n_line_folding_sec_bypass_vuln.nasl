###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_traffic_server_host_header_n_line_folding_sec_bypass_vuln.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# Apache Traffic Server (ATS) Host Header and Line Folding Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:apache:traffic_server';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812525");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2017-5660");
  script_tag(name:"last_modification", value: "$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value: "2018-02-28 12:10:48 +0530 (Wed, 28 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Apache Traffic Server (ATS) Host Header and Line Folding Security Bypass Vulnerability");

  script_tag(name: "summary", value: "This host is installed with Apache Traffic
  Server and is prone to security bypass vulnerability.");
 
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value: "The flaw exists due to an error in Host
  header and line folding.  This can have issues when interacting with upstream
  proxies and the wrong host being used.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain unauthorized access to certain resources. This may aid
  in further attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"
  Apache Traffic Server 6.2.0 and prior.

  Apache Traffic Server 7.0.0");

  script_tag(name:"solution", value:"Upgrade to 6.2.2, 7.1.2 or later. 
  For updates refer to http://trafficserver.apache.org");

  script_tag(name: "qod_type", value: "remote_banner");
  script_tag(name: "solution_type", value: "VendorFix");
  script_xref(name: "URL", value: "http://seclists.org/oss-sec/2018/q1/196");
  script_xref(name: "URL", value: "https://github.com/apache/trafficserver/pull/1657");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
atsVer = infos['version'];
atsPath = infos['location'];

if(atsVer == "7.0.0"){
  fix = "7.1.2"; 
}
else if(version_is_less(version:atsVer, test_version: "6.2.0")){
  fix =  "6.2.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version: atsVer, fixed_version: fix, install_path:atsPath);
  security_message(port: port, data: report);
  exit(0);
}
