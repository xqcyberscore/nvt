###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_ilo_61556.nasl 6074 2017-05-05 09:03:14Z teissa $
#
# HP Integrated Lights-Out Unspecified Authentication Bypass Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103782";
CPE = "cpe:/o:hp:integrated_lights-out";

tag_insight = "Bypass authentication via unknown vectors.";

tag_impact = "An attacker can exploit this issue to bypass the authentication
mechanism and perform unauthorized actions on the affected computer.
This may aid in further attacks.";

tag_affected = "HP Integrated Lights-Out 3 (aka iLO3) firmware before 1.60 and 4
(aka iLO4) firmware before 1.30";

tag_summary = "HP Integrated Lights-Out is prone to an authentication-bypass
vulnerability.";

tag_solution = "Updates are available.";
tag_vuldetect = "Check the firmware version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61556);
 script_cve_id("CVE-2013-4805");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
 script_version ("$Revision: 6074 $");

 script_name("HP Integrated Lights-Out  Unspecified Authentication Bypass Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61556");
 script_xref(name:"URL", value:"http://www.hp.com/");
 
 script_tag(name:"last_modification", value:"$Date: 2017-05-05 11:03:14 +0200 (Fri, 05 May 2017) $");
 script_tag(name:"creation_date", value:"2013-09-10 14:47:03 +0200 (Tue, 10 Sep 2013)");
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

  if(int(ilo_vers) == 3)      t_vers = '1.60';
  else if(int(ilo_vers) == 4) t_vers = '1.30';

  if(version_is_less(version:fw_vers, test_version:t_vers)) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
