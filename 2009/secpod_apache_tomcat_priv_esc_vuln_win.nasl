###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_tomcat_priv_esc_vuln_win.nasl 7551 2017-10-24 12:24:05Z cfischer $
#
# Apache Tomcat Windows Installer Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901050");
  script_version("$Revision: 7551 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:24:05 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2009-11-17 15:16:05 +0100 (Tue, 17 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3548");
  script_bugtraq_id(36954);
  script_name("Apache Tomcat Windows Installer Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheTomcat/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3185");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Nov/1023146.html");

  tag_solution = "Apply patch from below link,
  http://svn.apache.org/viewvc?view=revision&revision=834047

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

  tag_impact = "Successful attempt could lead remote attackers to bypass security restrictions
  and gain the privileges.

  Impact Level: Application.";

  tag_affected = "Apache Tomcat version 5.5.0 to 5.5.28 and 6.0.0 through 6.0.20 on Windows.";

  tag_insight = "The flaw is due to the windows installer setting a blank password by default
  for the administrative user, which could be exploited by attackers to gain
  unauthorized administrative access to a vulnerable installation.";

  tag_summary = "Apache Tomcat Server is running on this host and that is prone to
  Privilege Escalation vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

# Check Tomcat version < 5.5.29, or < 6.0.21
if( version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.28" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.20" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.29/6.0.21" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
