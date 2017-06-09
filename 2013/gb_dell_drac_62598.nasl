###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_drac_62598.nasl 6074 2017-05-05 09:03:14Z teissa $
#
# Dell iDRAC6 and iDRAC7 'ErrorMsg' Parameter Cross Site Scripting Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103808";
CPE = "cpe:/h:dell:remote_access_card";

tag_insight = "Dell iDRAC 6 and Dell iDRAC 7 administrative web interface login page
can allow remote attackers to inject arbitrary script via the vulnerable query string
parameter ErrorMsg.";

tag_impact = "An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.";

tag_affected = "Dell iDRAC6 1.95 and previous versions
Dell iDRAC7 1.40.40 and previous versions

NOTE: iDRAC6 'modular' (blades) are not affected; no updates are required.";

tag_summary = "Dell iDRAC6 and iDRAC7 are prone to a cross-site scripting vulnerability
because they fails to properly sanitize user-supplied input.";

tag_solution = "Firmware updates will be posted to the Dell support page when available.
Users should download the appropriate update for the version of iDRAC they have installed:

iDRAC6 'monolithic' (rack and towers) - FW version 1.96; targeted release date is Q4CY13.
iDRAC7 all models - FW version 1.46.45; target release date is mid/late September 2013.";

tag_vuldetect = "Check the firmware version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(62598);
 script_cve_id("CVE-2013-3589");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version ("$Revision: 6074 $");

 script_name("Dell iDRAC6 and iDRAC7 'ErrorMsg' Parameter Cross Site Scripting Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62598");
 script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/920038");
 
 script_tag(name:"last_modification", value:"$Date: 2017-05-05 11:03:14 +0200 (Fri, 05 May 2017) $");
 script_tag(name:"creation_date", value:"2013-10-14 11:13:22 +0200 (Mon, 14 Oct 2013)");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_dell_drac_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_mandatory_keys("dell_remote_access_controller/fw_version");

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

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

dtyp = get_kb_item("dell_remote_access_controller/version");
if(dtyp !~ "^(6|7)$")exit(99);

fw_version = get_kb_item("dell_remote_access_controller/fw_version");
if(!fw_version)exit(0);

vuln = FALSE;

if(dtyp == "6") {
  if(version_is_less(version:fw_version, test_version:"1.96"))vuln = TRUE;
}

if(dtyp == "7") {
  if(version_is_less(version:fw_version, test_version:"1.46.45"))vuln = TRUE;
}

if(vuln) {
  security_message(port:port);
  exit(0);
}  

exit(99);
