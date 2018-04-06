###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_ivt_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# IBM WebSphere Application Server IVT Cross Site Scripting Vulnerability
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

tag_impact = "Successful exploitation will let attackers to conduct cross-site scripting
  attacks.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server (WAS) version 6.1 before 6.1.0.41
  IBM WebSphere Application Server (WAS) version 7.0 before 7.0.0.19";
tag_insight = "The flaw is due to an error in Installation Verification Test (IVT)
  application in the Install component, which allows remote attackers to inject
  arbitrary web script or HTML via unspecified vectors.";
tag_solution = "Upgrade to version 6.1.0.41 or 7.0.0.19 or later,
  For updates refer to  http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802413");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-1362");
  script_bugtraq_id(46736);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-18 18:06:52 +0530 (Wed, 18 Jan 2012)");
  script_name("IBM WebSphere Application Server IVT Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69731");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27007951");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM43792");

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
if(version_in_range(version: vers, test_version: "6.1", test_version2:"6.1.0.40")||
   version_in_range(version: vers, test_version: "7.0", test_version2:"7.0.0.18")){
  report = report_fixed_ver( installed_version:vers, fixed_version:'6.1.0.40/7.0.0.18' );
  security_message(port:0, data:report);
}
