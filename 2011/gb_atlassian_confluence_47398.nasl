###############################################################################
# OpenVAS Vulnerability Test
#
# Atlassian Confluence Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:atlassian:confluence";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103153");
  script_version("2019-10-15T06:15:50+0000");
  script_tag(name:"last_modification", value:"2019-10-15 06:15:50 +0000 (Tue, 15 Oct 2019)");
  script_tag(name:"creation_date", value:"2011-05-02 15:13:22 +0200 (Mon, 02 May 2011)");
  script_bugtraq_id(47398);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Atlassian Confluence Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/47398");
  script_xref(name:"URL", value:"http://jira.atlassian.com/browse/CONF-21508");
  script_xref(name:"URL", value:"http://jira.atlassian.com/browse/CONF-21819");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/DOC/Confluence+Security+Advisory+2011-01-18");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/DOC/Confluence+Security+Advisory+2011-03-24");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_atlassian_confluence_detect.nasl");
  script_mandatory_keys("atlassian/confluence/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Atlassian Confluence is prone to multiple cross-site scripting
  vulnerabilities because it fails to sufficiently sanitize user- supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Atlassian Confluence versions 2.7 through 3.4.8.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"2.7", test_version2:"3.4.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.4.9");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
