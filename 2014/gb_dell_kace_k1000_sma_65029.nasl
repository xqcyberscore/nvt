###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_k1000_sma_65029.nasl 2823 2016-03-10 07:27:58Z antu123 $
#
# Dell Kace 1000 Systems Management Appliance DS-2014-001 Multiple SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103892";
CPE = "cpe:/a:dell:x_dellkace";

tag_insight = "Dell Kace 1000 Systems Management Appliance is prone to multiple SQL-
injection vulnerabilities because it fails to sufficiently sanitize
user-supplied input before using it in an SQL query.";

tag_impact = "Exploiting these issues could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities in the
underlying database.";

tag_affected = "Dell Kace 1000 Systems Management Appliance 5.4.76847 is vulnerable;
other versions may also be affected.";

tag_summary = "Dell Kace 1000 Systems Management Appliance is prone to multiple SQL injection vulnerabilities";
tag_solution = "Updates are available.";
tag_vuldetect = "Check the version";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(65029);
 script_version ("$Revision: 2823 $");
 script_cve_id("CVE-2014-1671");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_name("Dell Kace 1000 Systems Management Appliance DS-2014-001 Multiple SQL Injection Vulnerabilities");


 script_xref(name:"URL", value:"http://www.baesystemsdetica.com.au/Research/Advisories/Dell-KACE-K1000-SQL-Injection-%28DS-2014-001%29");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65029");
 
 script_tag(name:"last_modification", value:"$Date: 2016-03-10 08:27:58 +0100 (Thu, 10 Mar 2016) $");
 script_tag(name:"creation_date", value:"2014-01-27 17:25:18 +0100 (Mon, 27 Jan 2014)");
 script_summary("Check the version");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_dell_kace_k1000_sma_detect.nasl");
 script_mandatory_keys("X-DellKACE/installed");
 script_require_ports("Services/www", 80);

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port (cpe:CPE, nvt:SCRIPT_OID) ) exit (0);
if( ! get_port_state (port) ) exit (0);

fix = '5.5';

if( vers = get_app_version (cpe:CPE, nvt:SCRIPT_OID, port:port) )
{
  if( version_is_less (version:vers, test_version:fix) )
  {
      report = 'Installed Version: ' + vers + '\nFixed Version:     ' + fix;
      security_message (port:port, data:report);
      exit (0);
  }
}

exit (99);
