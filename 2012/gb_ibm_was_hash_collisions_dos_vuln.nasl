###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_hash_collisions_dos_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# IBM WebSphere Application Server Hash Collisions DOS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attackers to cause a denial of service
  (CPU consumption) by sending many crafted parameters.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server (WAS) 6.0 to 6.0.2.43
  IBM WebSphere Application Server (WAS) 6.1 before 6.1.0.43
  IBM WebSphere Application Server (WAS) 7.0 before 7.0.0.23
  IBM WebSphere Application Server (WAS) 8.0 before 8.0.0.3";
tag_insight = "The flaw is due to an error in computing hash values for 'form'
  parameters without restricting the ability to trigger hash collisions
  predictably which allows remote attackers to cause a denial of service.";
tag_solution = "Upgrade to version 6.1.0.43 or 7.0.0.23 or 8.0.0.3 or later,
  For updates refer to http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to denial
  of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802418");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0193");
  script_bugtraq_id(51441);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-23 14:06:41 +0530 (Mon, 23 Jan 2012)");
  script_name("IBM WebSphere Application Server Hash Collisions DOS Vulnerability");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg24031821");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21577532");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM53930");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:ibm:websphere_application_server';

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

## Check for IBM WebSphere Application Server versions 6.1 before 6.1.0.41
if(version_in_range(version: vers, test_version: "6.0", test_version2:"6.0.2.43")||
   version_in_range(version: vers, test_version: "6.1", test_version2:"6.1.0.42")||
   version_in_range(version: vers, test_version: "7.0", test_version2:"7.0.0.22")||
   version_in_range(version: vers, test_version: "8.0", test_version2:"8.0.0.2")){
  report = report_fixed_ver( installed_version:vers, fixed_version:'See advisory' );
  security_message(port:0, data:report);
}
