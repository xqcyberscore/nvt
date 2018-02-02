###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elasticsearch_directory_traversal_vuln_lin.nasl 8613 2018-02-01 07:35:27Z cfischer $
#
# Elasticsearch Directory Traversal Vulnerability (Linux)
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

CPE = "cpe:/a:elasticsearch:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808502");
  script_version("$Revision: 8613 $");
  script_cve_id("CVE-2015-5531");
  script_bugtraq_id(75935);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-01 08:35:27 +0100 (Thu, 01 Feb 2018) $");
  script_tag(name:"creation_date", value:"2016-06-28 18:11:01 +0530 (Tue, 28 Jun 2016)");
  script_name("Elasticsearch Directory Traversal Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Elasticsearch
  and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The Flaw is due to an error in the
  snapshot API calls.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to read arbitrary files.

  Impact Level: Application");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"affected", value:"Elasticsearch version 1.0.0 through 1.6.0
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to Elasticsearch version 1.6.1,
  or later.
  For updates refer to https://www.elastic.co");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536017/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastsearch_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("elasticsearch/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 9200);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

#Variable initialize
esPort = "";
esVer = "";

# Get Port
if(!esPort = get_app_port(cpe:CPE)){
 exit(0);
}

## Get the version
if(!esVer = get_app_version(cpe:CPE, port:esPort)){
 exit(0);
}

if(version_in_range(version:esVer, test_version:"1.0.0", test_version2:"1.6.0"))
{
  report = report_fixed_ver(installed_version:esVer, fixed_version:"1.6.1");
  security_message(data:report, port:esPort);
  exit(0);
}
