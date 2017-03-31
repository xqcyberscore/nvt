###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joo_jstr_mul_vul_feb_15.nasl 5568 2017-03-14 10:00:33Z teissa $
#
# Joomla J2Store 3.1.6 multiple SQL injection vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

tag_impact = "Successful exploitation will allow an
  unauthenticated remote attacker to execute arbitrary SQL commands via the (1) sortby or (2) manufacturer_ids[] parameter to index.php.";

tag_insight = " The first vulnerability was in the sortby parameter within a request made
while searching for products. The second vulnerability was in an advanced search multipart form request,
within the manufacturer_ids parameters.";

tag_affected = "J2Store v3.1.6 and previous versions. ";

tag_summary = "Detection of installed version of Joomla J2Store. 

    The script detects the version of joomla J2Store component on remote host and tells whether it is vulnerable.";

tag_solution = "Fixed in J2Store v3.1.7 version. ";

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107024");
  script_version("$Revision: 5568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-14 11:00:33 +0100 (Tue, 14 Mar 2017) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-07-07 06:40:16 +0200 (Thu, 07 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla J2Store 3.1.6 multiple SQL injection vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning"); 
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

## Variable Initialization
appPort = 0;
dir = "";
url = "";

## Get  Port
if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Joomla Location
if(!dir = get_app_location(cpe:CPE, port:appPort)){
  exit(0);
}

url = dir + '/Joomla/administrator/components/com_j2store/com_j2store.xml';
sndReq = http_get( item: url, port:appPort );
rcvRes = http_keepalive_send_recv( port: appPort, data:sndReq, bodyonly:FALSE );
if ( rcvRes !~ "<extension version" && "J2Store" >!< rcvRes && "Joomla" >!< rcvRes) exit ( 0 );
if(ve = egrep( pattern:'<version>([0-9])+', string:rcvRes) )
{
tmpVer = eregmatch ( pattern:'<version>(([0-9])[.]([0-9])[.]([0-9]))', string: ve);
}

if(tmpVer[1] ) {
  jstrVer = tmpVer[1];
} 

if (version_is_less (version: jstrVer, test_version: "3.1.7"))
{
  report = 'Installed Version: ' + jstrVer + '\n' +
           'Fixed Version:     ' + "3.1.7 or higher" + '\n';

  security_message(data:report, port:jstrVer);
  exit(0);
}



