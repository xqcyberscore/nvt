###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_mult_vuln_jan13_win.nasl 5080 2017-01-24 11:02:59Z cfi $
#
# PostgreSQL 'xml_parse()' And 'xslt_process()' Multiple Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to modify data, obtain sensitive
  information or trigger outbound traffic to arbitrary external hosts.
  Impact Level: Application";

tag_affected = "PostgreSQL versions 8.3 before 8.3.20, 8.4 before 8.4.13,
  9.0 before 9.0.9, and 9.1 before 9.1.5 on Windows";
tag_insight = "- An error exists within the 'xml_parse()' function when parsing DTD data
    within XML documents.
  - An error exists within the 'xslt_process()' when parsing XSLT style sheets.";
tag_solution = "Upgrade to PostgreSQL 8.3.20, 8.4.13, 9.0.9 or 9.1.5 or later,
  For updates refer to http://www.postgresql.org/download/";
tag_summary = "This host is installed with PostgreSQL and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803219";
CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5080 $");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_bugtraq_id(55072, 55074);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:02:59 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2013-01-24 17:08:52 +0530 (Thu, 24 Jan 2013)");
  script_name("PostgreSQL 'xml_parse()' And 'xslt_process()' Multiple Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50218");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027408");
  script_xref(name : "URL" , value : "http://www.postgresql.org/about/news/1407");
  script_xref(name : "URL" , value : "http://www.postgresql.org/support/security");

  script_summary("Check for the version of PostgreSQL on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed","Host/runs_windows");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

pgsqlPort = "";
pgsqlVer = "";


## Exit if its not windows
if(host_runs("Windows") != "yes"){
  exit(0);
}

## Get the default port
pgsqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!pgsqlPort){
  pgsqlPort = 5432;
}

## Check the port status
if(!get_port_state(pgsqlPort)){
  exit(0);
}

## Get the PostgreSQL version
pgsqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:pgsqlPort);
if(isnull(pgsqlVer) ||  !(pgsqlVer =~ "^(8|9)")){
  exit(0);
}

## Check for vulnerable PostgreSQL versions
if(version_in_range(version:pgsqlVer, test_version:"8.3", test_version2:"8.3.19") ||
   version_in_range(version:pgsqlVer, test_version:"8.4", test_version2:"8.4.12") ||
   version_in_range(version:pgsqlVer, test_version:"9.0", test_version2:"9.0.8") ||
   version_in_range(version:pgsqlVer, test_version:"9.1", test_version2:"9.1.4")){
  security_message(port:pgsqlPort);
}
