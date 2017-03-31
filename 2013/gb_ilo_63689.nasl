###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ilo_63689.nasl 2939 2016-03-24 08:47:34Z benallard $
#
# HP Integrated Lights-Out Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103859";
CPE = "cpe:/o:hp:integrated_lights-out";

tag_insight = "HP Integrated Lights-Out is prone to a Cross Site Scripting
and an Information Disclosure Vulnerability.";

tag_impact = "An attacker may leverage this issue to obtain sensitive information
that may aid in further attacks or to execute arbitrary HTML and
script code in an unsuspecting user's browser in the context of the
affected site. This may allow the attacker to steal cookie-based
authentication credentials and launch other attacks.";

tag_affected = "Versions prior to HP Integrated Lights-Out 4 1.32 and HP Integrated
Lights-Out 3 1.65 are vulnerable.";

tag_summary = "HP Integrated Lights-Out is prone to multiple vulnerabilities.";
tag_solution = "Updates are available.";
tag_vuldetect = "Check the version of HP Integrated Lights-Out.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(63689,63691);
 script_cve_id("CVE-2013-4842","CVE-2013-4843");
 script_version ("$Revision: 2939 $");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

 script_name("HP Integrated Lights-Out Multiple Vulnerabilities");
 

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63689");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63691");
 
 script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:47:34 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2013-12-18 11:18:02 +0100 (Wed, 18 Dec 2013)");
 script_summary("Check the version of HP Integrated Lights-Out");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("ilo_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("HP_ILO/installed");

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

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(fw_vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(!ilo_vers = get_kb_item('www/' + port + '/HP_ILO/ilo_version'))exit(0);

  if(int(ilo_vers) == 3)      t_vers = '1.65';
  else if(int(ilo_vers) == 4) t_vers = '1.32';

  if(version_is_less(version:fw_vers, test_version:t_vers)) {

      report = 'ILO Generation: ' + ilo_vers + '\nInstalled Firmware Version: ' + fw_vers + '\nFixed Firmware Version:     ' + t_vers + '\n';

      security_message(port:port, data:report);
      exit(0);
  }

}

exit(99);
