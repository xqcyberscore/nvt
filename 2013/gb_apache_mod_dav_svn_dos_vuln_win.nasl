###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_dav_svn_dos_vuln_win.nasl 5080 2017-01-24 11:02:59Z cfi $
#
# Apache HTTP Server 'mod_dav_svn' Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "
  Impact Level: Application";

CPE = "cpe:/a:apache:http_server";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803743";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5080 $");
  script_cve_id("CVE-2013-1896");
  script_bugtraq_id(61129);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:02:59 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2013-08-21 18:57:17 +0530 (Wed, 21 Aug 2013)");
  script_name("Apache HTTP Server 'mod_dav_svn' Denial of Service Vulnerability (Windows)");

 tag_summary =
"The host is running Apache HTTP Server and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version Apache HTTP Server with the help of detect NVT
and check it is vulnerable or not.";

  tag_insight =
"The flaw is due to an error in 'mod_dav.c', It does not properly determine
whether DAV is enabled for a URI.";

  tag_impact =
"Successful exploitation will allow remote attacker to cause a denial of
service (segmentation fault) via a MERGE request in which the URI is
configured for handling by the mod_dav_svn module.";

  tag_affected =
"Apache HTTP Server version before 2.2.25 on windows.";

  tag_solution =
"Upgrade to Apache HTTP Server 2.2.25 or later,
For updates refer to http://svn.apache.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.apache.org/dist/httpd/Announcement2.2.html");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc/httpd/httpd/trunk/modules/dav/main/mod_dav.c?view=log");
  script_summary("Check for the version of Apache HTTP Server on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed","Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

# variable initialization
httpPort = 0;
httpVers = "";

## Exit if its not windows
if(host_runs("Windows") != "yes") exit(0);

# get the port
if(!httpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)) exit(0);

# check the port state
if(!get_port_state(httpPort)) exit(0);

# get the version
if(!httpVers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:httpPort)) exit(0);

# check the version
if(httpVers && httpVers >!< "unknown" &&
   version_is_less(version:httpVers, test_version:"2.2.25"))
{
  security_message(port:httpPort);
  exit(0);
}
