###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_epolicy_orchestrator_65771.nasl 2826 2016-03-10 08:19:43Z benallard $
#
# McAfee ePolicy Orchestrator XML External Entity Information Disclosure Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103925";
CPE = "cpe:/a:mcafee:epolicy_orchestrator";

tag_insight = "The Import and Export Framework in McAfee ePolicy Orchestrator
(ePO) before 4.6.7 Hotfix 940148 allows remote authenticated users with permissions
to add dashboards to read arbitrary files by importing a crafted XML file, related
to an XML External Entity (XXE) issue.";

tag_impact = "An attacker can exploit this issue to gain access to sensitive
information from the application; this may lead to further attacks.";

tag_affected = "McAfee ePolicy Orchestrator 4.6.7 and prior are vulnerable.";

tag_summary = "McAfee ePolicy Orchestrator is prone to an XML External Entity
vulnerability";

tag_solution = "Updates are available.";
tag_vuldetect = "Check the version";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(65771);
 script_cve_id("CVE-2014-2205");
 script_tag(name:"cvss_base", value:"6.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:N");
 script_version ("$Revision: 2826 $");

 script_name("McAfee ePolicy Orchestrator XML External Entity Information Disclosure Vulnerability");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65771");
 script_xref(name:"URL", value:"http://www.mcafee.com/us/enterprise/products/system_security_management/epolicy_orchestrator.html");
 
 script_tag(name:"last_modification", value:"$Date: 2016-03-10 09:19:43 +0100 (Thu, 10 Mar 2016) $");
 script_tag(name:"creation_date", value:"2014-03-20 11:41:18 +0100 (Thu, 20 Mar 2014)");
 script_summary("Check the installed version");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
 script_mandatory_keys("mcafee_ePO/installed");
 script_require_ports("Services/www", 8443);

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port(cpe:CPE, nvt:SCRIPT_OID ) ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );

if( vers =  get_app_version( cpe:CPE, nvt:SCRIPT_OID, port:port ) )
{
  if(version_is_less( version: vers, test_version: "4.6.7" ) )
  {
      report = 'Installed Version: ' + vers + 'Fixed Version:     4.6.7';

      security_message( port:port, data:report );
      exit(0);
  }
}

exit( 99 );
