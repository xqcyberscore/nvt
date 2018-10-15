###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_session_fixation_vuln_win.nasl 11866 2018-10-12 10:12:29Z cfischer $
#
# Apache Tomcat Session Fixation Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803636");
  script_version("$Revision: 11866 $");
  script_cve_id("CVE-2013-2067");
  script_bugtraq_id(59799);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:12:29 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-06 12:57:30 +0530 (Thu, 06 Jun 2013)");
  script_name("Apache Tomcat Session Fixation Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheTomcat/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/84154");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1417891");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1408044");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct session fixation
  attacks to hijack the target user's session.");
  script_tag(name:"affected", value:"Apache Tomcat version 6.0.21 to 6.0.36 and 7.x before 7.0.33");
  script_tag(name:"insight", value:"Flaw due to improper validation of session cookies in the FormAuthenticator
  module in 'java/org/apache/catalina/authenticator/FormAuthenticator.java'.");
  script_tag(name:"summary", value:"The host is running Apache Tomcat Server and is prone to session
  fixation vulnerability.");
  script_tag(name:"solution", value:"Apply patch or upgrade Apache Tomcat to 7.0.33 or 6.0.37 or later.

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tomcat.apache.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"6.0.21", test_version2:"6.0.36" ) ||
    version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.32" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0.37/7.0.33" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );