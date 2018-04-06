###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_plugin_key_info_disc_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# IBM WebSphere Application Server 'plugin-key.kdb' Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_solution = "Apply the patch,
  http://www-01.ibm.com/support/docview.wss?uid=swg21591172

  *****
  NOTE : Ignore this warning, if above patch has been applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to gain sensitive
  information.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server (WAS) 8.0 and prior";
tag_insight = "The flaw is due to an error in the Plug-in, which uses unencrypted
  HTTP communication after expiration of the plugin-key.kdb password. Which
  allows remote attackers to sniff the network, or spoof arbitrary server
  and further perform a man-in-the-middle (MITM) attacks to obtain sensitive
  information.";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802851");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2162");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-11 17:31:58 +0530 (Fri, 11 May 2012)");
  script_name("IBM WebSphere Application Server 'plugin-key.kdb' Information Disclosure Vulnerability");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74900");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21591172");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21588312");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:ibm:websphere_application_server';

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

## Check for IBM WebSphere Application Server <= 8.0
if(version_is_less_equal(version: vers, test_version:"8.0")){
  report = report_fixed_ver( installed_version:vers, fixed_version:'8.0' );
  security_message(port:0, data:report);
}
