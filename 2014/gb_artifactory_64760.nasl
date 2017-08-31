###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_artifactory_64760.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Artifactory XStream Remote Code Execution Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103919";
CPE = "cpe:/a:jfrog:artifactory";

tag_insight = "Artifactory prior to version 3.1.1.1 using a XStream library
which is prone to a remote code execution vulnerability.";

tag_impact = "Successfully exploiting this issue may allow an attacker to execute
arbitrary code in the context of the user running the affected
application.";

tag_affected = "Artifactory < 3.1.1.1";
tag_summary = "Artifactory is prone to a remote code-execution vulnerability.";
tag_solution = "Update to Artifactory 3.1.1.1";
tag_vuldetect = "Check the installed version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(64760);
 script_cve_id("CVE-2013-7285");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 6759 $");

 script_name("Artifactory XStream Remote Code Execution Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64760");
 script_xref(name:"URL", value:"http://www.jfrog.com/confluence/display/RTF/Artifactory+3.1.1");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-03-13 10:30:44 +0100 (Thu, 13 Mar 2014)");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_artifactory_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("artifactory/installed");

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

if( ! port = get_app_port( cpe:CPE, nvt:SCRIPT_OID ) ) exit( 0 );
if( vers = get_app_version( cpe:CPE, nvt:SCRIPT_OID, port:port ) )
{
  if( version_is_less( version: vers, test_version: "3.1.1.1" ) )
  {
      report = 'Installed version: ' + vers + '\nFixed version:     3.1.1.1';

      security_message( port:port, data:report );
      exit(0);
  }
}

exit(0);
