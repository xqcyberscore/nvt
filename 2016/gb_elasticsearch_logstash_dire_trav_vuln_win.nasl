###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_logstash_dire_trav_vuln_win.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# Elasticsearch Logstash Directory Traversal Vulnerability (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:elasticsearch:logstash";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808094");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2015-4152");
  script_bugtraq_id(75112);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-06-23 16:16:20 +0530 (Thu, 23 Jun 2016)");
  script_name("Elasticsearch Logstash Directory Traversal Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Elasticsearch Logstash
  and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The Flaw is due to improper validation of
  path option in file output plugin.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to write to arbitrary files.

  Impact Level: Application");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Elasticsearch Logstash version prior to
  1.4.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Elasticsearch Logstash version 1.4.3,
  or later.
  For updates refer to https://www.elastic.co");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535725/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elasticsearch_logstash_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Elastisearch/Logstash/Installed","Host/runs_windows");
  script_require_ports("Services/www", 9200);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

#Variable initialize
esPort = "";
esVer = "";

## Get Port
if(!esPort = get_app_port(cpe:CPE)){
 exit(0);
}

## Get the version
if(!esVer = get_app_version(cpe:CPE, port:esPort)){
 exit(0);
}

if(version_is_less(version:esVer, test_version:"1.4.3"))
{
  report = report_fixed_ver(installed_version:esVer, fixed_version:"1.4.3");
  security_message(data:report, port:esPort);
  exit(0);
}
