###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_CSCuf49554.nasl 6093 2017-05-10 09:03:18Z teissa $
#
# Cisco NX-OS Denial of Service Vulnerability
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

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103818";

tag_insight = "This issue is being tracked by Cisco bug ID CSCuf49554.";
tag_impact = "An attacker can exploit this issue to cause the affected device to reload, denying service to legitimate users.";
tag_affected = "Cisco Nexus 7000 Series running on NX-OS.";
tag_summary = "Cisco NX-OS is prone to a denial-of-service vulnerability.";

tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

tag_vuldetect = "Check the NX OS version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(62446);
 script_cve_id("CVE-2013-1121");
 script_tag(name:"cvss_base", value:"5.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
 script_version ("$Revision: 6093 $");

 script_name("Cisco NX-OS Denial of Service Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62446");
 script_xref(name:"URL", value:"http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCuf49554");

 script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
 script_tag(name:"creation_date", value:"2013-10-22 17:24:45 +0200 (Tue, 22 Oct 2013)");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("CISCO");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_cisco_nx_os_version.nasl");
 script_mandatory_keys("cisco_nx_os/version","cisco_nx_os/model","cisco_nx_os/device");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if(!nx_model = get_kb_item("cisco_nx_os/model"))exit(0);
if(!nx_ver = get_kb_item("cisco_nx_os/version"))exit(0);

if( nx_model !~ "^7" ) exit(0);

vers = ereg_replace(pattern:'[()]', replace:".", string:nx_ver);
vers = ereg_replace(pattern:'\\.$', replace:"", string:vers);

ff    = make_list("5.2.1.N1.3","6.0.2.N2.1");
fixed = '6.2.1.81.S0';

foreach first_found (ff) {
  if (revcomp(a:vers, b:first_found) >= 0) {
    security_message(port:0, data:'Installed Version: ' + nx_ver + '\nFixed Version:     6.2(1.81)S0');
    exit(0);
 
  }  
}

exit(99);


