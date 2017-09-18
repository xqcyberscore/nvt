###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nx_os_65074.nasl 7140 2017-09-15 09:41:22Z cfischer $
#
# Cisco NX-OS Label Distribution Protocol Message Remote Denial of Service Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103888";

tag_insight = "This issue is being tracked by Cisco Bug ID CSCul88851.";

tag_impact = "Successfully exploiting this issue allows remote attackers to cause
denial-of-service conditions.";

tag_affected = "Cisco Nexus 7000 Series Switches running NX-OS 6.2(2)S42";
tag_summary = "Cisco NX-OS is prone to a remote denial-of-service vulnerability.";
tag_solution = "Ask the Vendor for an update.";

tag_vuldetect = "Check the NX OS version.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(65074);
 script_cve_id("CVE-2014-0677");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version ("$Revision: 7140 $");

 script_name("Cisco NX-OS Label Distribution Protocol Message Remote Denial of Service Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65074");
 script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-0677");
 
 script_tag(name:"last_modification", value:"$Date: 2017-09-15 11:41:22 +0200 (Fri, 15 Sep 2017) $");
 script_tag(name:"creation_date", value:"2014-01-23 12:42:53 +0100 (Thu, 23 Jan 2014)");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("CISCO");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
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

if ( ! nx_model = get_kb_item( "cisco_nx_os/model" ) )   exit( 0 );
if ( ! nx_ver   = get_kb_item( "cisco_nx_os/version" ) ) exit( 0 );

if ( nx_model !~ "^7"  ) exit(99);

if ( nx_ver  == "6.2(2)S42" )
{
  security_message(port:0, data:'Installed Version: ' + nx_ver + '\nFixed Version:     NA');
  exit(0);
}

exit(99);
