###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2014-0004_remote.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# VMSA-2014-0004: VMware product updates address OpenSSL security vulnerabilities (remote check)
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

tag_summary = "VMware product updates address OpenSSL security vulnerabilities.";
tag_solution = "Apply the missing patch(es).";

tag_affected = "ESXi 5.5 without patch ESXi550-201404020
ESXi 5.5 Update 1 without patch ESXi550-201404001 ";

tag_vuldetect = "Check the build number.";

tag_insight = 'a. Information Disclosure vulnerability in OpenSSL third party library

The OpenSSL library is updated to version openssl-1.0.1g to resolve multiple security issues

The Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned the names
CVE-2014-0076 and CVE-2014-0160 to these issues.';

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105022");
 script_cve_id("CVE-2014-0076","CVE-2014-0160");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 9354 $");
 script_name("VMSA-2014-0004 VMware product updates address OpenSSL security vulnerabilities");


 script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0004.html");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2014-05-08 13:04:01 +0100 (Thu, 08 May 2014)");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_vmware_esx_web_detect.nasl");
 script_mandatory_keys("VMware/ESX/build","VMware/ESX/version");

 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");

 exit(0);

}

include("vmware_esx.inc");

if( ! esxVersion = get_kb_item( "VMware/ESX/version" ) ) exit( 0 );
if( ! esxBuild = get_kb_item( "VMware/ESX/build" ) ) exit( 0 );

fixed_builds = make_array( "5.5.0","1746974" );

if( ! fixed_builds[esxVersion] ) exit( 0 );

if( int( esxBuild ) < int( fixed_builds[esxVersion] ) )
{
  security_message(port:0, data: esxi_remote_report( ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion] ) );
  exit( 0 );
}

exit( 99 );
