###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_tomcat_sec_bypass_vuln.nasl 4346 2016-10-25 12:54:45Z cfi $
#
# Apache Tomcat Security bypass vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901114");
  script_version("$Revision: 4346 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-25 14:54:45 +0200 (Tue, 25 Oct 2016) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-1157");
  script_bugtraq_id(39635);
  script_name("Apache Tomcat Security bypass vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheTomcat/installed");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510879");

  tag_impact = "Remote attackers can exploit this issue to obtain the host name or IP address
  of the Tomcat server. Information harvested may aid in further attacks.

  Impact Level: Application";

  tag_affected = "Apache Tomcat version 5.5.0 to 5.5.29
  Apache Tomcat version 6.0.0 to 6.0.26";

  tag_insight = "The flaw is caused by 'realm name' in the 'WWW-Authenticate' HTTP header for
  'BASIC' and 'DIGEST' authentication that might allow remote attackers to
  discover the server's hostname or IP address by sending a request for a resource.";

  tag_solution = "Upgrade to the latest version of Apache Tomcat 5.5.30 or 6.0.27 or later,
  For updates refer to http://tomcat.apache.org";

  tag_summary = "This host is running Apache Tomcat server and is prone to security
  bypass vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Grep for affected Tomcat Versions
if( version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.29" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.26" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.30/6.0.27" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );