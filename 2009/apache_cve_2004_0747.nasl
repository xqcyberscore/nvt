##############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_cve_2004_0747.nasl 9219 2018-03-27 11:58:13Z cfischer $
#
# Apache Web Server Configuration File Environment Variable Local
# Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100172");
  script_version("$Revision: 9219 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-27 13:58:13 +0200 (Tue, 27 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-0747");
  script_bugtraq_id(11182);
  script_name("Apache Web Server Configuration File Environment Variable Local Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11182");

  tag_summary = "According to its version number, the remote version of Apache Web
  Server is prone to a local buffer-overflow vulnerability that
  affects a configuration file environment variable.";

  tag_insight= "The flas occurs because the application fails to validate user-supplied
  string lengths before copying them into finite process buffers.";

  tag_impact = "An attacker may leverage this issue to execute arbitrary code on
  the affected computer with the privileges of the Apache webserver process.";

  tag_solution = "The vendor has released an upgrade. Please see
  http://www.apache.org/dist/httpd/Announcement2.html for more
  information.";

  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.0.51" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.51" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );